"""Repair GDB/pwndbg symbols for this project's native FGKASLR libraries.

    source /absolute/project/native/debug/gdb_fgkaslr.py
    start
    break puts

Symbol repair never writes inferior memory or original ELF files. A temporary
view carries relocated function symbols and the live unwind sections. This is
not a DWARF line-table/variable-location rewriter. Linux x86-64, metadata v5.
SPDX-License-Identifier: 0BSD
"""

import atexit
import bisect
import re
import struct
import tempfile
from collections import deque
from pathlib import Path

MARK = 0x46474B41534C52
MAGIC = 0x314E474652444C
MASK = (1 << 64) - 1


class ElfImage:
    """Small standalone ELF reader; no project imports or third-party packages."""

    def __init__(self, path):
        self.data = Path(path).read_bytes()
        if self.data[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("expected little-endian ELF64")
        h = self.unpack("<HHIQQQIHHHHHH", 16)
        if h[1] != 62 or h[10] != 64 or not h[11] or h[12] >= h[11]:
            raise ValueError("expected x86-64 ELF with section headers")
        self.sections = []
        for i in range(h[11]):
            values = self.unpack("<IIQQQQIIQQ", h[5] + i * 64)
            self.sections.append(
                dict(
                    zip(
                        (
                            "name_offset",
                            "type",
                            "flags",
                            "addr",
                            "offset",
                            "size",
                            "link",
                            "info",
                            "align",
                            "entsize",
                        ),
                        values,
                    ),
                    index=i,
                )
            )
        strings = self.section_data(self.sections[h[12]])
        for section in self.sections:
            section["name"] = self.string(strings, section["name_offset"])
        if h[9] and h[8] != 56:
            raise ValueError("unexpected ELF program header size")
        self.segments = [
            dict(
                zip(
                    (
                        "type",
                        "flags",
                        "offset",
                        "vaddr",
                        "paddr",
                        "filesz",
                        "memsz",
                        "align",
                    ),
                    self.unpack("<IIQQQQQQ", h[4] + i * 56),
                )
            )
            for i in range(h[9])
        ]

    def unpack(self, fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(self.data):
            raise ValueError("truncated ELF structure")
        return struct.unpack_from(fmt, self.data, offset)

    def section_data(self, section):
        start, size = section["offset"], section["size"]
        if start + size > len(self.data):
            raise ValueError("truncated ELF section")
        return self.data[start : start + size]

    @staticmethod
    def string(data, offset):
        end = data.find(b"\0", offset)
        if not 0 <= offset <= end < len(data):
            raise ValueError("invalid ELF string")
        return data[offset:end].decode("utf-8", errors="replace")


def parse_process_mappings(text):
    """GDB's Linux mapping table, including anonymous RX/PROT_NONE spans."""
    result = []
    pattern = re.compile(
        r"^\s*(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s+"
        r"0x[\da-fA-F]+\s+(0x[\da-fA-F]+)\s+"
        r"([r-][w-][x-][ps-])(?:\s+(.*?))?\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            start, end, offset = (int(match[i], 16) for i in (1, 2, 3))
            result.append((start, end, offset, match[4], match[5] or ""))
    if not result:
        raise ValueError(
            "Linux mapping permissions unavailable; use a local Linux/WSL inferior"
        )
    return result


def is_executable_range(maps, address, size=1):
    """Check that a complete live range belongs to an executable mapping."""
    return any(
        a <= address and address + size <= b and "x" in mode
        for a, b, _, mode, _ in maps
    )


def find_code_unit(starts, units, address):
    """Return a zero-based code-unit index, excluding each unit's end address."""
    index = bisect.bisect_right(starts, address) - 1
    return index if index >= 0 and address - starts[index] < units[index][1] else None


def build_symbol_view(path, base, read_memory, maps):
    """Return a debugger ELF view, or None if the object has not shuffled yet."""
    elf = ElfImage(path)
    segment = next((p for p in elf.segments if p["paddr"] == MARK), None)
    if segment is None:
        return None
    header = bytes(read_memory(base, 64))
    if header[:24] != elf.data[:24] or header[32:] != elf.data[32:64]:
        raise ValueError("mapped ELF header differs from local file: " + str(path))
    h = elf.unpack("<15Q", segment["offset"])
    if h[0] != MAGIC or h[1] != 5:
        raise ValueError("expected native metadata version 5: " + str(path))
    count, patch_count, lo, hi, fixed = h[2], h[3], h[5], h[6], h[13]
    if not 0 < count <= 100000 or patch_count > 1000000 or fixed > patch_count:
        raise ValueError("invalid native counts")
    core = 120 + count * 40 + patch_count * 32 + h[4] * 16
    if core > h[12] or h[12] > segment["filesz"] or not lo < hi:
        raise ValueError("invalid native metadata size")
    offset = segment["offset"] + 120
    units = [elf.unpack("<QQQIIII", offset + i * 40) for i in range(count)]
    starts = [u[0] for u in units]
    for i, u in enumerate(units):
        if (
            not u[1]
            or not u[2]
            or u[2] & (u[2] - 1)
            or u[2] > 4096
            or u[0] < lo
            or u[0] + u[1] > hi
            or (i and units[i - 1][0] + units[i - 1][1] > u[0])
        ):
            raise ValueError("invalid native unit bounds/alignment/order")
    offset += count * 40
    patches = [elf.unpack("<QQQIBBBB", offset + i * 32) for i in range(patch_count)]
    dynsym = next((s for s in elf.sections if s["type"] == 11), None)
    if dynsym is None:
        raise ValueError("missing dynamic symbols")
    live_dynsym = bytes(read_memory(base + dynsym["addr"], dynsym["size"]))
    original = elf.section_data(dynsym)
    changed = any(
        live_dynsym[i + 8 : i + 16] != original[i + 8 : i + 16]
        for i in range(0, len(original), 24)
        if original[i + 4] & 15 in (2, 10) and original[i + 6 : i + 8] != b"\0\0"
    )
    if not changed:
        return None

    # Fixed dynsym and unwind patches retain an observable anchor for functions,
    # including hidden/static symbols which never appeared in .dynsym.
    safe_names = (".dynsym", ".eh_frame", ".eh_frame_hdr")
    snapshots = {}
    for section in elf.sections:
        if section["name"] in safe_names and section["size"]:
            snapshots[section["index"]] = (
                live_dynsym
                if section is dynsym
                else bytes(read_memory(base + section["addr"], section["size"]))
            )
    destinations = {}
    queue = deque()

    def record_unit_destination(index, value):
        if not 0 <= index < count:
            raise ValueError("invalid patch unit index")
        value &= MASK
        if value < lo or value + units[index][1] > hi or value % units[index][2]:
            raise ValueError("live relocation outside native pool")
        if index in destinations:
            if destinations[index] != value:
                raise ValueError("inconsistent live relocation anchors")
        else:
            destinations[index] = value
            queue.append(index)

    def decode_patch_destination(patch, raw, delta=0):
        _, value, bias, target, relative, width, signed, _ = patch
        encoded = int.from_bytes(raw, "little", signed=bool(signed))
        return (encoded - (bias - delta if relative else 0) - value) & MASK

    for p in patches[:fixed]:
        if not p[3]:
            continue
        for section in elf.sections:
            if section["index"] not in snapshots:
                continue
            at = p[0] - section["addr"]
            if 0 <= at and at + p[5] <= section["size"]:
                record_unit_destination(
                    p[3] - 1,
                    decode_patch_destination(
                        p, snapshots[section["index"]][at : at + p[5]]
                    ),
                )
                break

    # A remaining unit can be recovered from a direct call/LEA in an anchored
    # function. Never read excluded units or infer a destination from disk order.
    while queue:
        source = queue.popleft()
        dst = destinations[source]
        u = units[source]
        if not is_executable_range(maps, base + dst, u[1]):
            continue
        if u[3] + u[4] > patch_count:
            raise ValueError("invalid patch group")
        code = None
        for p in patches[u[3] : u[3] + u[4]]:
            if not p[3] or p[3] - 1 in destinations:
                continue
            if code is None:
                code = bytes(read_memory(base + dst, u[1]))
            at = p[0] - u[0]
            if not 0 <= at <= len(code) - p[5]:
                raise ValueError("patch escapes source unit")
            record_unit_destination(
                p[3] - 1, decode_patch_destination(p, code[at : at + p[5]], dst - u[0])
            )

    data = bytearray(elf.data)
    symbols = []
    removed = []
    unresolved = set()
    versions = {}
    for section in elf.sections:
        if section["type"] != 2:
            continue
        strings = elf.section_data(elf.sections[section["link"]])
        for at in range(section["offset"], section["offset"] + section["size"], 24):
            name, info, _, ndx, value, _ = elf.unpack("<IBBHQQ", at)
            name = elf.string(strings, name)
            if ndx and info & 15 in (2, 10) and "@" in name:
                bare, version = name.split("@", 1)
                key = (bare, value)
                if key not in versions or version.startswith("@"):
                    versions[key] = (version.lstrip("@"), version.startswith("@"))
    new_strings = {}

    def append_debugger_symbol_name(section, name):
        index = section["link"]
        table = new_strings.setdefault(
            index, bytearray(elf.section_data(elf.sections[index]))
        )
        offset = len(table)
        table.extend(name.encode("utf-8") + b"\0")
        return offset

    shoff = struct.unpack_from("<Q", data, 40)[0]
    text = next(s for s in elf.sections if s["name"] == ".text")
    if text["addr"] > lo or text["addr"] + text["size"] > hi:
        raise ValueError("unexpected native text section")
    # .fgspace supplies additional destinations beyond the original .text end.
    struct.pack_into("<Q", data, shoff + text["index"] * 64 + 32, hi - text["addr"])
    for section in elf.sections:
        if section["index"] in snapshots:
            at = section["offset"]
            data[at : at + section["size"]] = snapshots[section["index"]]
        if section["name"] == ".fgspace":
            struct.pack_into("<Q", data, shoff + section["index"] * 64 + 8, 0)
        if (
            section["name"].startswith((".debug", ".zdebug", ".gnu_debug"))
            or section["name"] == ".note.gnu.build-id"
        ):
            # Avoid importing obsolete external DWARF via the original build ID.
            struct.pack_into("<I", data, shoff + section["index"] * 64 + 4, 0)
            struct.pack_into("<Q", data, shoff + section["index"] * 64 + 32, 0)
        if section["type"] not in (2, 11):
            continue
        strings = elf.section_data(elf.sections[section["link"]])
        for at in range(section["offset"], section["offset"] + section["size"], 24):
            name, info, other, ndx, old, size = elf.unpack("<IBBHQQ", at)
            if (
                ndx >= len(elf.sections)
                or not ndx
                or not elf.sections[ndx]["flags"] & 4
                or info & 15 in (3, 4)
            ):
                continue
            index = find_code_unit(starts, units, old)
            new = old
            reason = None
            if index is not None:
                if index not in destinations:
                    reason = "unresolved"
                    unresolved.add(index)
                else:
                    new = destinations[index] + old - units[index][0]
                    if not is_executable_range(maps, base + new, max(size, 1)):
                        reason = "excluded"
            elif lo <= old < hi:
                reason = "unowned pool label"
            symbol_name = elf.string(strings, name)
            is_function = info & 15 in (2, 10)
            if reason:
                struct.pack_into("<HQQ", data, at + 6, 0, 0, 0)
                if is_function and symbol_name:
                    removed.append((symbol_name, reason))
                continue
            struct.pack_into("<Q", data, at + 8, new)
            if info & 15 == 10:
                # Treat resolver entries as ordinary debugger functions: symbol
                # lookup must not execute a resolver inside the stopped inferior.
                data[at + 4] = (info & 0xF0) | 2
            if is_function and symbol_name:
                bare = symbol_name.split("@", 1)[0]
                version = versions.get((bare, old))
                if version:
                    if section["type"] == 11 and not version[1]:
                        # Do not let a non-default dynsym version shadow the
                        # canonical name in GDB's minimal-symbol lookup.
                        struct.pack_into("<I", data, at, 0)
                    elif section["type"] == 2:
                        label = (
                            bare
                            if version[1]
                            else bare
                            + "__fg_compat_"
                            + re.sub(r"[^\w]", "_", version[0])
                        )
                        struct.pack_into(
                            "<I", data, at, append_debugger_symbol_name(section, label)
                        )
                symbol = dict(
                    name=symbol_name,
                    address=base + new,
                    size=size,
                    ifunc=(info & 15) == 10,
                    default=False,
                )
                symbols.append(symbol)
                if "@@" in symbol_name:
                    symbols.append(
                        dict(symbol, name=symbol_name.split("@@", 1)[0], default=True)
                    )
    for index, table in new_strings.items():
        if elf.sections[index]["flags"] & 2:
            raise ValueError("static symbol strings unexpectedly allocated")
        struct.pack_into("<QQ", data, shoff + index * 64 + 24, len(data), len(table))
        data.extend(table)
    if unresolved:
        raise ValueError(
            "%d named code units lack live anchors; symbols not installed"
            % len(unresolved)
        )
    return dict(
        data=bytes(data),
        symbols=symbols,
        removed=removed,
        translated=len(destinations),
        units=count,
        text=base + text["addr"],
        bootstrap=bool(h[10]),
    )


try:
    import gdb
except ImportError:
    gdb = None


if gdb is not None:

    class LayoutController:
        def __init__(self):
            self.enabled = False
            self.busy = False
            self.pid = None
            self.loaded = {}
            self.normal = set()
            self.address_breakpoints = []
            self.temp = tempfile.TemporaryDirectory(prefix="fg-gdb-")
            atexit.register(self.temp.cleanup)
            self.settings = {}
            self.last_error = None
            gdb.events.stop.connect(self.on_stop)
            gdb.events.exited.connect(self.on_reset)
            gdb.events.clear_objfiles.connect(self.on_reset)
            for name in (
                "fg-on",
                "fg-off",
                "fg-refresh",
                "fg-status",
                "fg-address",
                "fg-break",
            ):
                LayoutCommand(name, self)
            self.enable()

        @staticmethod
        def execute(command):
            return gdb.execute(command, from_tty=False, to_string=True)

        @staticmethod
        def quote(value):
            return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

        def unload_symbol_views(self):
            for item in self.loaded.values():
                path = str(item["file"])
                if any(o.filename == path for o in gdb.objfiles()):
                    self.execute("remove-symbol-file " + self.quote(path))
                item["file"].unlink(missing_ok=True)
            self.loaded.clear()
            self.normal.clear()
            self.pid = None

        def on_reset(self, event):
            if self.busy:
                return
            self.busy = True
            try:
                self.clear_address_breakpoints()
                self.unload_symbol_views()
            except (gdb.error, OSError):
                self.loaded.clear()
                self.normal.clear()
                self.pid = None
            finally:
                self.busy = False

        def clear_address_breakpoints(self):
            for breakpoint in self.address_breakpoints:
                if breakpoint.is_valid():
                    breakpoint.delete()
            self.address_breakpoints.clear()

        def enable(self):
            if not self.enabled:
                self.settings = {
                    name: gdb.parameter(name)
                    for name in ("auto-solib-add", "trust-readonly-sections")
                }
                self.execute("set auto-solib-add off")
                self.execute("set trust-readonly-sections off")
                self.enabled = True
            if gdb.selected_inferior().pid:
                self.refresh()

        def disable(self):
            self.busy = True
            try:
                self.clear_address_breakpoints()
                self.unload_symbol_views()
                for name, value in self.settings.items():
                    self.execute("set %s %s" % (name, "on" if value else "off"))
                self.enabled = False
                if gdb.selected_inferior().pid:
                    self.execute("sharedlibrary")
            finally:
                self.busy = False
            gdb.write(
                "FGKASLR: disabled; original disk symbols restored (not layout-corrected).\n"
            )

        def refresh(self, force=False):
            if self.busy or not self.enabled:
                return
            inferior = gdb.selected_inferior()
            if not inferior.pid:
                raise gdb.GdbError("start/attach the inferior first")
            self.busy = True
            added = []
            try:
                if force or self.pid != inferior.pid:
                    self.unload_symbol_views()
                    self.pid = inferior.pid
                maps = parse_process_mappings(self.execute("info proc mappings"))
                objects = {
                    (a, path)
                    for a, _, off, _, path in maps
                    if off == 0 and path.startswith("/")
                }
                alive = {
                    (base, path)
                    for base, path in objects
                    if (base, path) in self.loaded
                }
                for key in list(self.loaded):
                    if key not in alive:
                        item = self.loaded.pop(key)
                        if any(o.filename == str(item["file"]) for o in gdb.objfiles()):
                            self.execute(
                                "remove-symbol-file " + self.quote(item["file"])
                            )
                        item["file"].unlink(missing_ok=True)
                normal = set()
                for base, path in sorted(objects):
                    key = (base, path)
                    if key in self.loaded:
                        continue
                    if path in self.normal:
                        normal.add(path)
                        continue
                    if not Path(path).is_file():
                        continue
                    try:
                        elf = ElfImage(path)
                    except (OSError, ValueError):
                        continue
                    if not any(p["paddr"] == MARK for p in elf.segments):
                        normal.add(path)
                        continue
                    view = build_symbol_view(path, base, inferior.read_memory, maps)
                    if view is None:
                        continue
                    directory = Path(self.temp.name) / ("%d-%x" % (inferior.pid, base))
                    directory.mkdir(parents=True, exist_ok=True)
                    view["file"] = directory / Path(path).name
                    view["file"].write_bytes(view.pop("data"))
                    view.update(base=base, path=path)
                    added.append((key, view))
                if added or force:
                    # Remove stale solib symbols, not the executable's symbols.
                    # add-symbol-file views are user-loaded and survive this.
                    self.execute("nosharedlibrary")
                    self.normal.clear()
                # A mapping may appear before GDB's solib rendezvous notices it.
                # Retry normal libraries at every stop; GDB skips loaded ones.
                # GDB's basic regexp dialect is not Python's grouping dialect.
                for path in sorted(normal):
                    self.execute("sharedlibrary ^" + re.escape(path) + "$")
                self.normal = normal
                if added or force:
                    # Match normal loader/libc symbol precedence: ld has hidden
                    # malloc/memcpy helpers with the same unqualified names.
                    for key, view in sorted(
                        added, key=lambda item: not item[1]["bootstrap"]
                    ):
                        self.execute(
                            "add-symbol-file %s -o %#x"
                            % (self.quote(view["file"]), view["base"])
                        )
                        self.loaded[key] = view
                    gdb.invalidate_cached_frames()
                    for _, view in added:
                        count = len(
                            {(s["name"], s["address"]) for s in view["symbols"]}
                        )
                        gdb.write(
                            "FGKASLR: %s @ %#x: %d live symbols, %d excluded/omitted.\n"
                            % (
                                Path(view["path"]).name,
                                view["base"],
                                count,
                                len(view["removed"]),
                            )
                        )
                self.last_error = None
            finally:
                self.busy = False

        def on_stop(self, event):
            if not self.enabled or self.busy:
                return
            try:
                self.refresh()
            except (gdb.error, OSError, ValueError, struct.error) as error:
                message = str(error)
                if message != self.last_error:
                    gdb.write(
                        "FGKASLR: refresh failed: %s; use fg-refresh after start.\n"
                        % message,
                        gdb.STDERR,
                    )
                    self.last_error = message

        def print_status(self):
            gdb.write(
                "FGKASLR: %s; %d corrected objects.\n"
                % ("on" if self.enabled else "off", len(self.loaded))
            )
            for view in self.loaded.values():
                gdb.write("  %#x %s\n" % (view["base"], view["path"]))

        def resolve_symbol_address(self, argument, breakpoint=False):
            args = gdb.string_to_argv(argument)
            if len(args) not in (1, 2):
                raise gdb.GdbError(
                    "usage: fg-address/fg-break SYMBOL [PATH_FRAGMENT|0xBASE]"
                )
            self.refresh()
            found = {}
            excluded = False
            for view in self.loaded.values():
                if (
                    len(args) == 2
                    and args[1] not in view["path"]
                    and args[1] != hex(view["base"])
                ):
                    continue
                matches = [s for s in view["symbols"] if s["name"] == args[0]]
                defaults = [s for s in matches if s["default"]]
                for symbol in defaults or matches:
                    found[symbol["address"]] = (view, symbol)
                excluded |= any(name == args[0] for name, _ in view["removed"])
            if not found:
                raise gdb.GdbError(
                    "function excluded by policy"
                    if excluded
                    else "no live native symbol; stop at main, then fg-refresh"
                )
            for address, (view, symbol) in sorted(found.items()):
                gdb.write(
                    "%s: %s = %#x%s\n"
                    % (
                        view["path"],
                        args[0],
                        address,
                        (
                            " (IFUNC resolver, not necessarily selected implementation)"
                            if symbol["ifunc"]
                            else ""
                        ),
                    )
                )
            if len(found) != 1:
                raise gdb.GdbError(
                    "multiple versions/namespaces; select a versioned name and/or 0xBASE from fg-status"
                )
            address, (_, symbol) = next(iter(found.items()))
            gdb.set_convenience_variable("fg_address", gdb.Value(address))
            if breakpoint:
                self.address_breakpoints.append(gdb.Breakpoint("*%#x" % address))

    class LayoutCommand(gdb.Command):
        def __init__(self, name, controller):
            super().__init__(name, gdb.COMMAND_USER)
            self.name = name
            self.controller = controller

        def invoke(self, argument, from_tty):
            self.dont_repeat()
            c = self.controller
            try:
                if self.name == "fg-on":
                    c.enable()
                elif self.name == "fg-off":
                    c.disable()
                elif self.name == "fg-status":
                    c.print_status()
                elif self.name == "fg-refresh":
                    c.refresh(force=True)
                else:
                    c.resolve_symbol_address(argument, self.name == "fg-break")
            except (OSError, ValueError, struct.error) as error:
                raise gdb.GdbError(str(error))

    if not hasattr(gdb, "_fgkaslr_controller"):
        gdb._fgkaslr_controller = LayoutController()
        gdb.write(
            "FGKASLR: enabled. Use start (or attach), then normal break/disassemble; fg-status for objects.\n"
        )
    else:
        gdb.write("FGKASLR: already sourced; use fg-on / fg-refresh.\n")
