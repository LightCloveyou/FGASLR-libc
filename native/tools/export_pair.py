"""Compile retained linker relocations into an allocated native FGKASLR table.

This is a build step. The resulting ELF needs no Python, sidecar or launcher.
PT_NOTE for the build ID is reused as a final PT_LOAD; GNU_PROPERTY is kept.
"""

import argparse
from bisect import bisect_right
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from libc_layout.metadata import prepare
from libc_layout.elf import ELF
from libc_layout.core import sha256, save_json

MAGIC = 0x314E474652444C
MARK = 0x46474B41534C52
MASK = (1 << 64) - 1


def build_indexed_patch(dest, patch, units, starts):
    """Resolve unit indices and fold relocation arithmetic, modulo 2**64."""

    def unit_index(value):
        if value is None:
            return 0
        index = bisect_right(starts, value) - 1
        return (
            index + 1
            if index >= 0 and value - starts[index] < units[index]["size"]
            else 0
        )

    value = patch["value"] & MASK
    vi = unit_index(value)
    pi = unit_index(patch["place"])
    kind = patch["kind"]
    bias = patch["bias"]
    place = patch["place"]
    if kind == "absolute":
        bias = 0
    elif kind == "pcrel":
        bias = -place - bias
    elif kind == "symbol_pcrel":
        bias -= place
    elif kind == "anchored_pcrel":
        bias -= value
    else:
        raise ValueError("unknown native patch kind " + kind)
    if vi:
        value -= starts[vi - 1]
    if pi and not (
        starts[pi - 1] <= dest
        and dest + patch["width"] <= starts[pi - 1] + units[pi - 1]["size"]
    ):
        raise ValueError("moving patch destination crosses its source unit")
    if patch["width"] not in (4, 8):
        raise ValueError("unsupported native patch width")
    return (
        dest,
        value,
        bias & MASK,
        vi,
        pi,
        int(kind != "absolute"),
        patch["width"],
        int(patch["signed"]),
        0,
        0,
    )


def materialize_bss_tail(raw):
    """Make the original final LOAD's zero tail file-backed before adding a LOAD.

    Older Linux interpreter loading performs BSS completion only after all LOADs.
    Appending metadata beyond BSS makes that algorithm miss the original tail.
    Preserve all virtual addresses; move only non-allocated file sections.
    """
    b = bytearray(raw)
    elf = ELF("<native BSS preparation>", bytes(b))
    loads = [(i, p) for i, p in enumerate(elf.segments) if p["type"] == 1]
    tails = [(i, p) for i, p in loads if p["memsz"] > p["filesz"]]
    if not tails:
        return b, []
    if len(tails) != 1 or tails[0][0] != loads[-1][0]:
        raise ValueError("native BSS preparation requires one original final LOAD tail")
    index, p = tails[0]
    cut = p["offset"] + p["filesz"]
    zeros = p["memsz"] - p["filesz"]
    # Whole pages preserve the file alignment of displaced non-allocated sections.
    # rtld's early calloc also uses the remainder of the final mapped page and
    # assumes it is zero. Keep non-allocated bytes beyond that entire page.
    mapped_zero_bytes = ((p["vaddr"] + p["memsz"] + 4095) & -4096) - (
        p["vaddr"] + p["filesz"]
    )
    growth = (mapped_zero_bytes + 4095) & -4096
    if any(
        s["type"] != 8
        and s["flags"] & 2
        and s["size"]
        and s["offset"] + s["size"] > cut
        for s in elf.sections
    ):
        raise ValueError("allocated file data follows the proposed BSS insertion")
    phoff = struct.unpack_from("<Q", b, 32)[0]
    shoff = struct.unpack_from("<Q", b, 40)[0]
    if phoff + len(elf.segments) * 56 > cut or shoff < cut:
        raise ValueError("unexpected ELF table placement for BSS preparation")
    b[cut:cut] = bytes(growth)
    new_shoff = shoff + growth
    struct.pack_into("<Q", b, 40, new_shoff)
    for i, s in enumerate(elf.sections):
        # NOBITS describes a virtual zero range, not displaced bytes in the file.
        if s["type"] != 8 and s["offset"] >= cut:
            struct.pack_into("<Q", b, new_shoff + 64 * i + 24, s["offset"] + growth)
    for i, ph in enumerate(elf.segments):
        if ph["offset"] >= cut and ph["filesz"]:
            struct.pack_into("<Q", b, phoff + 56 * i + 8, ph["offset"] + growth)
    struct.pack_into("<Q", b, phoff + 56 * index + 32, p["memsz"])
    return b, [
        dict(
            vaddr=p["vaddr"] + p["filesz"],
            zero_bytes=zeros,
            mapped_zero_bytes=mapped_zero_bytes,
            inserted_file_bytes=growth,
        )
    ]


def file_offset_to_address(elf, off, width):
    """Translate a fully file-backed range, or return None for unmapped data."""
    for p in elf.segments:
        if (
            p["type"] == 1
            and p["offset"] <= off
            and off + width <= p["offset"] + p["filesz"]
        ):
            return p["vaddr"] + off - p["offset"]
    return None


def build_policy_metadata(elf, units, patches, fixed_patches, entry):
    """Build a name index and conservative startup roots once per library build."""
    starts = [u["start"] for u in units]

    def find_unit_index(value):
        i = bisect_right(starts, value) - 1
        return i + 1 if i >= 0 and value - starts[i] < units[i]["size"] else 0

    aliases = {}
    by_name = {}
    for dynamic in (False, True):
        for s in elf.symbols(dynamic=dynamic):
            if s["type"] not in (2, 10) or not s["section"]:
                continue
            unit = find_unit_index(s["value"])
            if not unit:
                continue
            name = s["name"].split("@", 1)[0]
            aliases[(name, unit)] = aliases.get((name, unit), 0) | (
                0x80000000 if dynamic else 0
            )
            by_name.setdefault(name, set()).add(unit)
    roots = set()
    for p in patches[:fixed_patches]:
        if not p[3]:
            continue
        section = next(
            (
                s["name"]
                for s in elf.sections
                if s["type"] != 8
                and s["flags"] & 2
                and s["addr"] <= p[0] < s["addr"] + s["size"]
            ),
            "<LOAD>",
        )
        if section not in (".dynsym", ".eh_frame", ".eh_frame_hdr"):
            roots.add(p[3])
    for name in (
        "__libc_start_main",
        "__libc_early_init",
        "malloc",
        "calloc",
        "realloc",
        "free",
    ):
        roots.update(by_name.get(name, ()))
    if find_unit_index(entry):
        roots.add(find_unit_index(entry))
    for section in elf.sections:
        if section["type"] != 4 or not section["flags"] & 2:
            continue
        symbols = elf.sections[section["link"]]
        strings = elf.section_data(elf.sections[symbols["link"]])
        for at in range(section["offset"], section["offset"] + section["size"], 24):
            _, info, _ = elf.unpack("<QQq", at)
            si = info >> 32
            if not si:
                continue
            name_at = elf.unpack("<I", symbols["offset"] + si * 24)[0]
            name = elf.string(strings, name_at).split("@", 1)[0]
            roots.update(by_name.get(name, ()))
    strings = bytearray()
    records = []
    offsets = {}
    for (name, unit), exported in sorted(aliases.items()):
        if name not in offsets:
            offsets[name] = len(strings)
            strings.extend(name.encode("ascii") + b"\0")
        records.append((offsets[name], unit | exported))
    size = 32 + 8 * len(records) + 4 * len(roots) + len(strings)
    result = bytearray(struct.pack("<4Q", len(records), len(roots), len(strings), size))
    for row in records:
        result.extend(struct.pack("<II", *row))
    for unit in sorted(roots):
        result.extend(struct.pack("<I", unit))
    result.extend(strings)
    return result


def export_native_image(image, link_map, records, out, report):
    """Validate a staged ELF before atomically replacing one output file.

    Callers deploying a pair must still switch a versioned directory; two
    separate renames cannot make a live ld/libc pair update atomic.
    """
    out = Path(out)
    report = Path(report)
    out.parent.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".fg-export-", dir=out.parent) as directory:
        stage = Path(directory)
        result = _export_staged_image(
            image, link_map, records, stage / out.name, stage / "report.json"
        )
        result["image"] = str(out)
        os.replace(stage / out.name, out)
        save_json(report, result)
        shutil.copyfile(stage / "report.json.plan.json", str(report) + ".plan.json")
    return result


def _export_staged_image(image, link_map, records, out, report):
    plan = prepare(image, link_map, records, str(report) + ".plan.json")
    elf = ELF(image)
    if any(s["name"] == ".note.stapsdt" and s["size"] for s in elf.sections):
        raise ValueError(
            "native export requires SystemTap probes disabled; movable debugger probe sites are unsupported"
        )
    units = plan["units"]
    boot = next((s for s in elf.sections if s["name"] == ".fgboot" and s["size"]), None)
    space = next(s for s in elf.sections if s["name"] == ".fgspace")
    lo = plan["region"][0]
    hi = space["addr"] + space["size"]
    worst = sum(u["size"] + u["alignment"] - 1 + 15 for u in units)
    if hi - lo < worst or not space["flags"] & 4:
        raise ValueError(
            "insufficient executable capacity for every aligned permutation"
        )
    textseg = next(
        p
        for p in elf.segments
        if p["type"] == 1 and p["vaddr"] <= lo < p["vaddr"] + p["filesz"]
    )
    if hi > textseg["vaddr"] + textseg["filesz"] or textseg["flags"] != 5:
        raise ValueError("permutation pool must occupy one executable mapping")
    code_lo = lo & -4096
    code_hi = (hi + 4095) & -4096
    if boot and code_lo < boot["addr"] + boot["size"] and boot["addr"] < code_hi:
        raise ValueError("replacement pages overlap the bootstrap")
    patches = []
    starts = [u["start"] for u in units]
    for p in plan["patches"]:
        dest = file_offset_to_address(elf, p["offset"], p["width"])
        if dest is None:
            continue  # debug/symtab/static RELA are not mapped at run time
        if boot and boot["addr"] <= dest < boot["addr"] + boot["size"]:
            # The nucleus remains RX throughout. Its only reference to movable
            # code is _fg_start's pre-shuffle fallback address for _start.
            continue
        record = build_indexed_patch(dest, p, units, starts)
        if not record[4] and any(
            dest < b < dest + p["width"] for b in [code_lo, code_hi]
        ):
            raise ValueError("fixed patch crosses a replacement page boundary")
        patches.append(record)
    frames = plan["eh_frame_table"]
    entries = frames["entries"] if frames else []
    if entries:
        table_va = file_offset_to_address(elf, frames["offset"], 8 * len(entries))
        if table_va is None or (
            table_va < code_hi and table_va + 8 * len(entries) > code_lo
        ):
            raise ValueError("unwind table overlaps replacement pages or is unmapped")
    # Fixed records precede source-unit groups. The runtime walks groups in the
    # chosen destination order: copy and patch each function while it is hot.
    patch_groups = [[] for _ in range(len(units) + 1)]
    frame_groups = [[] for _ in range(len(units) + 1)]
    for dest, value, bias, vi, pi, relative, width, sign, reserved, padding in patches:
        patch_groups[pi].append((dest, value, bias, vi, relative, width, sign, 0))
    for pc, fde in entries:
        i = bisect_right(starts, pc) - 1
        group = i + 1 if i >= 0 and pc - starts[i] < units[i]["size"] else 0
        if not group and lo <= pc < hi:
            raise ValueError("unwind PC in unowned pool bytes")
        frame_groups[group].append((pc - starts[i] if group else pc, fde))
    for group in patch_groups:
        group.sort(key=lambda p: p[0])
    for group in frame_groups:
        group.sort(key=lambda f: f[0])
    fixed_patches = len(patch_groups[0])
    fixed_frames = len(frame_groups[0])
    unit_records = []
    pi = fixed_patches
    fi = fixed_frames
    for i, u in enumerate(units):
        unit_records.append(
            (
                u["start"],
                u["size"],
                u["alignment"],
                pi,
                len(patch_groups[i + 1]),
                fi,
                len(frame_groups[i + 1]),
            )
        )
        pi += len(patch_groups[i + 1])
        fi += len(frame_groups[i + 1])
    packed_patches = [p for group in patch_groups for p in group]
    packed_frames = [f for group in frame_groups for f in group]
    entry = next(
        (s["value"] for s in elf.symbols() if s["name"] == "_start"), elf.entry
    )
    if boot and (boot["addr"] % 4096 or boot["size"] % 4096):
        raise ValueError("bootstrap must occupy whole pages")
    policy = build_policy_metadata(elf, units, packed_patches, fixed_patches, entry)
    size = (
        15 * 8 + 40 * len(units) + 32 * len(patches) + 16 * len(entries) + len(policy)
    )
    header = [
        MAGIC,
        5,
        len(units),
        len(patches),
        len(entries),
        lo,
        hi,
        frames["base"] if frames else 0,
        (
            file_offset_to_address(elf, frames["offset"], 8 * len(entries))
            if frames
            else 0
        ),
        entry,
        boot["addr"] if boot else 0,
        boot["addr"] + boot["size"] if boot else 0,
        size,
        fixed_patches,
        fixed_frames,
    ]
    data = bytearray(struct.pack("<15Q", *header))
    for record in unit_records:
        data.extend(struct.pack("<QQQIIII", *record))
    for p in packed_patches:
        data.extend(struct.pack("<QQQIBBBB", *p))
    for pc, fde in packed_frames:
        data.extend(struct.pack("<Qq", pc, fde))
    data.extend(policy)
    assert len(data) == size
    # Prepare against the original link, then strip debug while keeping alloc VAs.
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["objcopy", "--strip-debug", str(image), str(out)], check=True)
    stripped = ELF(out)
    b = bytearray(stripped.data)
    if boot:
        policy = next(
            s
            for s in stripped.symbols()
            if s["name"] in ("fg_metadata_required", "fg_required")
        )
        from libc_layout.metadata import va_offset

        struct.pack_into("<Q", b, va_offset(stripped, policy["value"], 8), 1)
    b, bss_records = materialize_bss_tail(b)
    stripped = ELF(out, bytes(b))
    phoff = struct.unpack_from("<Q", b, 32)[0]
    note = next(
        (
            i
            for i, p in enumerate(stripped.segments)
            if p["type"] == 4
            and any(
                s["name"] == ".note.gnu.build-id" and s["offset"] == p["offset"]
                for s in stripped.sections
            )
        ),
        None,
    )
    if note is None:
        raise ValueError("no reusable build-ID PT_NOTE")
    fileoff = (len(b) + 4095) & -4096
    va = (
        max(p["vaddr"] + p["memsz"] for p in stripped.segments if p["type"] == 1) + 4095
    ) & -4096
    if any(p["type"] == 1 for p in stripped.segments[note + 1 :]):
        raise ValueError("metadata PT_LOAD would not follow the existing LOADs")
    # Old interpreter loaders can unconditionally zero the final partial page.
    # A partial final read-only LOAD can fail before _fg_start is ever reached.
    mapped_size = (len(data) + 4095) & -4096
    struct.pack_into(
        "<II6Q",
        b,
        phoff + note * 56,
        1,
        4,
        fileoff,
        va,
        MARK,
        mapped_size,
        mapped_size,
        4096,
    )
    b.extend(bytes(fileoff - len(b)))
    b.extend(data)
    b.extend(bytes(mapped_size - len(data)))
    out.write_bytes(b)
    out.chmod(0o755)
    funcs = elf.functions()
    functions = {f["value"] for f in funcs}
    moving = {
        f["value"]
        for f in funcs
        if any(u["start"] <= f["value"] < u["start"] + u["size"] for u in units)
    }
    grouped = [u for u in units if len({f["offset"] for f in u["functions"]}) > 1]
    result = dict(
        image=str(out),
        sha256=sha256(out),
        native=True,
        metadata_bytes=size,
        metadata_version=5,
        native_policy_notes=True,
        patch_record_bytes=32,
        indexed_patch_references=True,
        fixed_patches=fixed_patches,
        fixed_frames=fixed_frames,
        grouped_patch_stream=True,
        linear_unwind_rebuild=True,
        code_commit="mprotect RX then mremap MAYMOVE|FIXED",
        code_mapping="anonymous private RX",
        unused_tail="complete unused pages never populated, then protected PROT_NONE",
        metadata_residency="MADV_DONTNEED after generation; late policy checks refault name index; advice failure is nonfatal",
        maximum_random_gap=15,
        alignment_counts={
            str(a): sum(u["alignment"] == a for u in units)
            for a in sorted({u["alignment"] for u in units})
        },
        unwind_sort="linear merge in permutation order",
        bss_file_backing=bss_records,
        metadata_mapping_bytes=mapped_size,
        legacy_interpreter_layout_compatible=True,
        units=len(units),
        patches=len(patches),
        identified_function_entries=len(functions),
        moving_function_entries=len(moving),
        grouped_units=grouped,
        fixed_functions=[f["name"] for f in funcs if f["value"] not in moving],
        bootstrap_bytes=boot["size"] if boot else 0,
        every_aligned_permutation_fits=True,
        pool_capacity=hi - lo,
        worst_case_capacity=worst,
        independent_function_sections=not grouped,
    )
    save_json(report, result)
    if grouped:
        raise ValueError(
            "native export rejected: multiple function entries remain in one unit"
        )
    if any(
        f["value"] not in moving
        and not (boot and boot["addr"] <= f["value"] < boot["addr"] + boot["size"])
        for f in funcs
    ):
        raise ValueError("native export rejected: an original function remains fixed")
    return result


def export_companion_libraries(build, out):
    names = {
        "libm.so",
        "libmvec.so",
        "libpthread.so",
        "libdl.so",
        "librt.so",
        "libresolv.so",
        "libutil.so",
        "libnsl.so",
        "libanl.so",
        "libthread_db.so",
        "libnss_files.so",
        "libnss_dns.so",
        "libnss_compat.so",
        "libnss_db.so",
        "libnss_hesiod.so",
        "libBrokenLocale.so",
    }
    result = {}
    # Direct build subdirectories only: never accidentally collect stale copies
    # or linker scripts from an earlier make-check testroot.
    for source in Path(build).glob("*/*.so"):
        if source.name not in names or source.is_symlink():
            continue
        try:
            dynamic = subprocess.check_output(
                ["readelf", "-dW", str(source)], text=True, stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            continue
        m = re.search(r"\(SONAME\).*\[([^\]]+)\]", dynamic)
        if not m or "/" in m[1]:
            raise ValueError("invalid companion SONAME")
        target = Path(out) / m[1]
        subprocess.run(
            ["objcopy", "--strip-debug", str(source), str(target)], check=True
        )
        result[m[1]] = sha256(target)
    save_json(Path(out) / "companions.json", result)
    # Ordinary gcc -L<out> -lc must link this pair, not the system libc script.
    shutil.copyfile(Path(build) / "libc_nonshared.a", Path(out) / "libc_nonshared.a")
    (Path(out) / "libc.so").write_text(
        "GROUP ( libc.so.6 libc_nonshared.a AS_NEEDED ( ld-linux-x86-64.so.2 ) )\n"
    )
    for soname in result:
        if ".so." in soname:
            (Path(out) / (soname.split(".so.", 1)[0] + ".so")).write_text(
                "INPUT ( " + soname + " )\n"
            )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--reports", required=True, type=Path)
    args = parser.parse_args()
    args.reports.mkdir(parents=True, exist_ok=True)
    results = {}
    for image, name in [
        (args.build / "build/libc.so", "libc.so.6"),
        (args.build / "build/elf/ld.so", "ld-linux-x86-64.so.2"),
    ]:
        link_map = Path(str(image) + ".fg.map")
        if not link_map.exists():
            link_map = image.with_name("ld.so.new.fg.map")
        results[name] = export_native_image(
            image,
            link_map,
            args.build / "records",
            args.out / name,
            args.reports / (name + ".json"),
        )
    export_companion_libraries(args.build / "build", args.out)
    print(
        json.dumps(
            {
                k: {f: v for f, v in x.items() if f != "grouped_units"}
                for k, x in results.items()
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
