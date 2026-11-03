"""Build-time extraction and identity checks for native ELF relocation metadata.

No application processing or runtime launcher. The native loader performs all
per-process code generation.
"""
import bisect
import json
import os
import re
import struct
import subprocess
from pathlib import Path

from .core import map_order, save_json, sha256
from .elf import ELF


def va_offset(elf, address, size=1):
    for p in elf.segments:
        if p["type"] == 1 and p["vaddr"] <= address and address + size <= p["vaddr"] + p["filesz"]:
            return p["offset"] + address - p["vaddr"]
    raise ValueError(f"virtual address 0x{address:x}+{size} has no file backing")


def instructions(path):
    result = subprocess.run(["objdump", "-d", "-w", str(path)], check=True,
                            stdout=subprocess.PIPE, text=True, env=dict(os.environ, LC_ALL="C"))
    insns = []
    pattern = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)[ \t]*(.*)$")
    for line in result.stdout.splitlines():
        m = pattern.match(line)
        if m:
            insns.append((int(m[1], 16), len(m[2].split()), m[3]))
    return sorted(insns)


def input_code_anchors(link_map, units):
    """Recover the code-unit anchor of data PC32 relocations before ld merges symbols.

    A jump-table entry can encode label - table_base, not label - entry.
    The relocatable input's symbol section identifies which WHOLE code unit
    supplies S, irrespective of its addend. This avoids guessing table bases.
    """
    text = Path(link_map).read_text().split("Linker script and memory map", 1)[1]
    code = {u["name"]: u["start"] for u in units}
    extra_code = {(u["input_file"], u["input_section"]): u["start"] for u in units if "input_file" in u}
    pattern = re.compile(r"^[ \t]+(\.[^\s]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)[ \t]+([^\n]+)", re.M)
    cache, result = {}, {}
    for match in pattern.finditer(text):
        section_name, address, size, filename = match.groups()
        filename = filename.strip()
        archive = re.fullmatch(r"(.+\.a)\(([^()]+)\)", filename)
        if not Path(filename).is_file() and not (archive and Path(archive[1]).is_file()):
            continue
        if filename not in cache:
            try:
                obj = ELF(filename, subprocess.check_output(["ar", "p", archive[1], archive[2]])) if archive else ELF(filename)
            except (ValueError, OSError):
                cache[filename] = None
                continue
            cache[filename] = (obj, obj.symbols()) if obj.type == 1 else None
        cached = cache[filename]
        if cached is None:
            continue
        obj, symbols = cached
        sections = [s for s in obj.sections if s["name"] == section_name]
        if len(sections) != 1:
            continue
        source = sections[0]
        if not source["flags"] & 2 or source["flags"] & (4 | 16) or section_name == ".eh_frame":
            continue
        for rs in obj.sections:
            if rs["type"] != 4 or rs["info"] != source["index"]:
                continue
            for off in range(rs["offset"], rs["offset"] + rs["size"], 24):
                place, info, addend = obj.unpack("<QQq", off)
                if info & 0xffffffff != 2:
                    continue
                symbol = symbols[info >> 32]
                if symbol["section"] >= len(obj.sections):
                    continue
                target_section = obj.sections[symbol["section"]]
                target_name = target_section["name"]
                if target_name in code:
                    result[int(address, 16) + place] = code[target_name]
                elif (filename, target_name) in extra_code:
                    result[int(address, 16) + place] = extra_code[filename, target_name]
                elif target_section["flags"] & 4:
                    result[int(address, 16) + place] = 0  # known fixed archive/startup code
    return result


def additional_text_units(elf, link_map):
    """Include linker-supplied code (notably libgcc) at whole-input-section granularity."""
    text = Path(link_map).read_text().split("Linker script and memory map", 1)[1]
    pattern = re.compile(r"^[ \t]+(\.text[^\s]*)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)[ \t]+([^\n]+)", re.M)
    result = []
    for match in pattern.finditer(text):
        name, start, size, filename = match.groups()
        start, size, filename = int(start, 16), int(size, 16), filename.strip()
        if not size or name.startswith(".text.fg."):
            continue
        archive = re.fullmatch(r"(.+\.a)\(([^()]+)\)", filename)
        if archive:
            obj = ELF(filename, subprocess.check_output(["ar", "p", archive[1], archive[2]]))
        elif Path(filename).is_file():
            obj = ELF(filename)
        else:
            raise ValueError("cannot identify text input: " + filename)
        sections = [s for s in obj.sections if s["name"] == name]
        if obj.type != 1 or len(sections) != 1 or sections[0]["size"] != size:
            raise ValueError("ambiguous linker-supplied code section")
        section = sections[0]
        funcs = [f for f in obj.functions() if f["section"] == section["index"]]
        unique = {f["value"] for f in funcs}
        result.append(dict(name="input:" + filename + ":" + name, start=start, size=size,
                           alignment=section["align"], file_offset=va_offset(elf, start, size),
                           input_file=filename, input_section=name,
                           functions=[dict(name=f["name"], offset=f["value"], size=f["size"]) for f in funcs],
                           limitation="multiple function entries in one section" if len(unique) > 1 else
                                      "no function symbol: granularity unknown" if not unique else None))
    return result


def prepare(image, link_map, records, output):
    elf = ELF(image)
    if elf.type != 3:
        raise ValueError("runtime preparation requires ET_DYN")
    rows = map_order(link_map)
    units_by_name = {}
    for f in sorted(Path(records).glob("*.json")):
        record = json.loads(f.read_text())
        for u in record["units"]:
            if u["randomized"]:
                units_by_name[u["randomized"]] = dict(u, object=record["object"])
    units = []
    for name, start, size in rows:
        if name not in units_by_name:
            raise ValueError("missing compile record for " + name)
        u = units_by_name[name]
        if size != u["bytes"]:
            raise ValueError("input section size changed during link: " + name)
        align = u.get("alignment")
        if align is None:
            raise ValueError("alignment missing from compile record; regenerate the record from its object")
        if align < 1 or align & (align - 1) or start % align:
            raise ValueError("invalid input section alignment")
        units.append(dict(name=name, start=start, size=size, alignment=align,
                          file_offset=va_offset(elf, start, size),
                          source_object=u["object"],
                          functions=[dict(name=f["name"], offset=f["value"], size=f["size"])
                                     for f in u["functions"]],
                          limitation=u["limitation"]))
    units.extend(additional_text_units(elf, link_map))
    units.sort(key=lambda u: u["start"])
    if any(a["start"] + a["size"] > b["start"] for a, b in zip(units, units[1:])):
        raise ValueError("overlapping input code units")
    text = next(s for s in elf.sections if s["name"] == ".text")
    if not all(text["addr"] <= u["start"] and u["start"] + u["size"] <= text["addr"] + text["size"] for u in units):
        raise ValueError("all movable units must occupy one .text output section")
    # Fail if non-padding, unaccounted bytes sit between independently movable units.
    # Alignment gaps may contain assembler/linker NOP encodings; preserve no semantic data there.
    # Coverage is established by link map + compile records; no byte disassembly heuristic is used for units.
    plan = dict(format=1, image_sha256=sha256(image), units=units,
                region=[units[0]["start"], units[-1]["start"] + units[-1]["size"]],
                patches=[], eh_frame_table=None, build_id=None, full_random=False)
    data_anchors = input_code_anchors(link_map, units)
    functions = elf.symbols()
    insns = instructions(image)
    inst_starts = [i[0] for i in insns]
    issues = []
    static_count = 0
    relocation_types = {}

    def patch(offset, width, kind, value, place=None, bias=0, signed=False):
        plan["patches"].append(dict(offset=offset, width=width, kind=kind, value=value,
                                    place=place, bias=bias, signed=signed))

    def code_address(value):
        return any(s["flags"] & 4 and s["addr"] <= value < s["addr"] + s["size"] for s in elf.sections)

    for rs in elf.sections:
        if rs["type"] == 19:  # SHT_RELR: relocation locations are encoded, pointed-to values are in data.
            cursor = 0
            for off in range(rs["offset"], rs["offset"] + rs["size"], 8):
                word = elf.unpack("<Q", off)[0]
                if not word & 1:
                    locations, cursor = [word], word + 8
                else:
                    locations = [cursor + 8 * i for i in range(63) if word & (1 << (i + 1))]
                    cursor += 63 * 8
                for loc in locations:
                    fileoff = va_offset(elf, loc, 8)
                    patch(fileoff, 8, "absolute", elf.unpack("<Q", fileoff)[0], place=loc)
            continue
        if rs["type"] != 4:
            continue
        if rs["entsize"] != 24 or rs["size"] % 24:
            raise ValueError("invalid RELA table")
        is_dynamic = bool(rs["flags"] & 2)
        source = elf.sections[rs["info"]] if rs["info"] else None
        if not is_dynamic and (source is None or not source["flags"] & 2):
            continue  # Debug info is deliberately not presented as runtime-correct.
        for off in range(rs["offset"], rs["offset"] + rs["size"], 24):
            place, info, addend = elf.unpack("<QQq", off)
            ty, sym = info & 0xffffffff, info >> 32
            relocation_types[str(ty)] = relocation_types.get(str(ty), 0) + 1
            if ty == 0:
                continue
            if is_dynamic:
                patch(off, 8, "absolute", place)
                if ty in (8, 37, 38):  # RELATIVE, IRELATIVE, RELATIVE64
                    patch(off + 16, 8, "absolute", addend, signed=True)
                elif ty not in (1, 5, 6, 7, 16, 17, 18, 36):
                    issues.append(f"dynamic relocation type {ty} at {place:#x}")
                continue
            static_count += 1
            patch(off, 8, "absolute", place)
            if ty in (2, 4, 9, 19, 20, 22, 34, 41, 42):
                fileoff = va_offset(elf, place, 4)
                value = elf.unpack("<i", fileoff)[0]
                bias = 0
                if source["flags"] & 4:
                    idx = bisect.bisect_right(inst_starts, place) - 1
                    if idx < 0:
                        issues.append(f"no instruction at {place:#x}"); continue
                    ip, length, asm = insns[idx]
                    if not (ip <= place and place + 4 <= ip + length):
                        issues.append(f"relocation outside instruction at {place:#x}"); continue
                    if "%rip" not in asm and not re.match(r"(?:bnd\s+)?(?:call|j\w+)\s", asm):
                        issues.append(f"unrecognized PC-relative instruction at {place:#x}: {asm}"); continue
                    bias = ip + length - place
                target = place + value + bias
                if not source["flags"] & 4 and place in data_anchors:
                    patch(fileoff, 4, "anchored_pcrel", data_anchors[place], place=place,
                          bias=value, signed=True)
                    continue
                # Non-executable PC32 references to code may be jump-table deltas with
                # a base other than P. Function-symbol references have an exact anchor.
                if not source["flags"] & 4 and source["name"] != ".eh_frame" and code_address(target):
                    symbol = functions[sym]
                    if symbol["type"] in (2, 10):
                        patch(fileoff, 4, "symbol_pcrel", symbol["value"], place=place,
                              bias=addend, signed=True)
                        continue
                    issues.append(f"ambiguous data-relative code target {source['name']} at {place:#x}")
                    continue
                patch(fileoff, 4, "pcrel", target, place=place, bias=bias, signed=True)
            elif ty in (1, 10, 11):
                width, signed = (8, False) if ty == 1 else (4, ty == 11)
                fileoff = va_offset(elf, place, width)
                value = int.from_bytes(elf.data[fileoff:fileoff + width], "little", signed=signed)
                patch(fileoff, width, "absolute", value, place=place, signed=signed)
            elif ty in (17, 18, 21, 23, 35):
                # TLS offsets and the TLSDESC call marker don't encode a code position.
                pass
            else:
                issues.append(f"unsupported static relocation type {ty} in {source['name']} at {place:#x}")

    if not static_count:
        issues.append("no retained static relocations; build with --emit-relocs")
    # Exported symbol values, local symbol values and ELF entry address.
    patch(24, 8, "absolute", elf.entry)
    for s in elf.sections:
        if s["type"] in (2, 11):
            for off in range(s["offset"], s["offset"] + s["size"], 24):
                _, info, _, ndx, value, _ = elf.unpack("<IBBHQQ", off)
                if ndx < len(elf.sections) and elf.sections[ndx]["flags"] & 4 and info & 15 != 3:
                    patch(off + 8, 8, "absolute", value)
        elif s["type"] == 6:
            for off in range(s["offset"], s["offset"] + s["size"], 16):
                tag, value = elf.unpack("<qQ", off)
                if tag in (12, 13):  # DT_INIT, DT_FINI
                    patch(off + 8, 8, "absolute", value)
        elif s["name"] == ".eh_frame_hdr":
            if elf.data[s["offset"]:s["offset"] + 4] != bytes((1, 0x1b, 3, 0x3b)):
                issues.append("unsupported .eh_frame_hdr pointer encoding")
                continue
            count = elf.unpack("<I", s["offset"] + 8)[0]
            if 12 + 8 * count > s["size"]:
                issues.append("truncated .eh_frame_hdr table"); continue
            entries = []
            for i in range(count):
                pc, fde = elf.unpack("<ii", s["offset"] + 12 + i * 8)
                entries.append([s["addr"] + pc, fde])
            plan["eh_frame_table"] = dict(offset=s["offset"] + 12, base=s["addr"], entries=entries)
        elif s["name"] in (".sframe", ".gnu.sframe") and s["size"]:
            issues.append("SFrame rebuilding is not implemented")
        elif s["name"] == ".note.gnu.build-id":
            namesz, descsz, kind = elf.unpack("<III", s["offset"])
            if namesz == 4 and kind == 3 and 16 + descsz <= s["size"] and 0 < descsz <= 32:
                plan["build_id"] = [s["offset"] + 16, descsz]
    plan["static_relocations"] = static_count
    plan["relocation_types"] = relocation_types
    plan["issues"] = issues
    plan["ready"] = not issues
    plan["limitations"] = [dict(name=u["name"], reason=u["limitation"],
                                 object=u.get("source_object", u.get("input_file")),
                                 functions=[f["name"] for f in u["functions"]],
                                 function_entries=len({f["offset"] for f in u["functions"]}))
                            for u in units if u["limitation"]]
    save_json(output, plan)
    if issues:
        raise ValueError(f"runtime preparation rejected {len(issues)} unsupported cases; see {output}")
    verify_identity(elf.data, plan)
    return plan


def verify_identity(data, plan):
    """Every encoded transformation must be a no-op before changing layout."""
    for p in plan["patches"]:
        if p["kind"] == "pcrel":
            value = p["value"] - p["place"] - p["bias"]
        elif p["kind"] == "symbol_pcrel":
            value = p["value"] + p["bias"] - p["place"]
        elif p["kind"] == "anchored_pcrel":
            value = p["bias"]
        else:
            value = p["value"]
        encoded = value.to_bytes(p["width"], "little", signed=p["signed"])
        offset = p["offset"]
        if not 0 <= offset <= len(data) - len(encoded) or data[offset:offset + len(encoded)] != encoded:
            raise ValueError("identity patch changes original bytes: preparation rejected")
    table = plan["eh_frame_table"]
    if table:
        for i, (pc, fde) in enumerate(sorted(table["entries"])):
            encoded = struct.pack("<ii", pc - table["base"], fde)
            offset = table["offset"] + i * 8
            if data[offset:offset + 8] != encoded:
                raise ValueError("identity unwind table changes original bytes: preparation rejected")
