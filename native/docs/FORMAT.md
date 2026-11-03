# Native ELF format — version 5

Private Linux x86-64 ELF64 little-endian format, 4096-byte pages. Rebuild and deploy ld/libc together. Not compatible with version 4.

## Library metadata

The build-ID PT_NOTE is reused as a read-only PT_LOAD after the original LOADs. Its `p_paddr` is `0x46474b41534c52`; file offset and virtual address are page-congruent. GNU_PROPERTY is retained. Structures follow in this order:

| Structure | Layout |
| --- | --- |
| Header, 120 bytes | 15 u64: magic, version, units, patches, frames, pool_lo, pool_hi, eh_base, eh_table, original_entry, boot_lo, boot_hi, total_bytes, fixed_patches, fixed_frames |
| Unit, 40 bytes | u64 original_start, size, alignment; u32 patch_first, patch_count, frame_first, frame_count |
| Patch, 32 bytes | u64 original_destination, value, folded_bias; u32 value_unit; u8 relative, width, signed, reserved |
| Frame, 16 bytes | u64 pc; i64 fde_delta |
| Policy index header, 32 bytes | u64 name_count, root_count, string_bytes, policy_index_bytes |
| Name, 8 bytes each | u32 string_offset; u32 unit_with_export_bit |
| Root, 4 bytes each | u32 one-based unit index |
| Strings | NUL-terminated names, byte aligned |

Magic is `0x314e474652444c`; version is 5. Addresses are ELF virtual offsets, not process pointers. Units are sorted by original_start. `value_unit` is one-based, zero means fixed. Moving values store offsets within units; fixed values retain all 64 bits.

Patch/frame groups have a fixed prefix followed by an exact contiguous interval per source unit. Groups cover the arrays once. Frame PCs are sorted per group; moving PCs are within-unit offsets, fixed PCs are original virtual offsets. FDE values are signed offsets from eh_base.

For source displacement `delta = dst[source] - original_start[source]`, write at `original_destination + delta`. Resolve value through value_unit, then add `folded_bias - delta` for relative patches. Bias incorporates original relocation-place arithmetic. Arithmetic is modulo 2^64; 32-bit encodings are checked for overflow.

Names are sorted lexicographically; equal names may name multiple symbol versions/units. Bit 31 of unit_with_export_bit marks a dynamic exported function. Remaining bits hold a one-based unit index. Roots conservatively include startup entries, data/relocation references and libc's own symbolic imports. Dynsym and unwind references alone are not roots. Function-to-function dependencies reuse Patch.value_unit; no second edge table is needed.

The consumer bounds counts, byte sizes, strings and unit references. It validates pool capacity, nonoverlapping units, alignments, exhaustive groups, destinations, permissions, unwind encoding and bootstrap isolation. Invalid metadata exits 127. This is trusted-build metadata, not a signature or a general hostile-ELF parser.

## Main executable policy note

The public header emits retained allocated `.note.fgpolicy` records, consumed through PT_NOTE without needing section headers:

- namesz = 4; descsz = 140; type = `0x46475031`.
- Owner is four bytes `FGP\0`.
- Descriptor: u32 magic `0x46504731`, version 1, action; char name[128].
- Actions: 1 allow, 2 deny, 4 whitelist, 5 blacklist. Mode notes have an empty name.
- Each complete note is 156 bytes, aligned to 4.

A retained relocation in `.data.rel.ro.fg_policy` references `_dl_fg_policy_v1` in ld (GLIBC_PRIVATE). This prevents normal linking/loading against an unmodified loader from silently ignoring policy. It is not cryptographic policy authentication. Manual ELF edits remain outside this mechanism.

## Startup

1. Native ld enters fixed `_fg_start`, randomizes its original rtld functions, then jumps to translated `_start` with the original stack.
2. At the end of `_dl_map_object_deps`, before relocations/IFUNC, the bridge reads main policy notes and mapped objects' undefined relocation symbols.
3. For policy libc, select the conservative dependency closure; an explicit deny of a selected unit exits 127. Without policy, retain all units.
4. Shuffle selected units with fresh kernel getrandom, unbiased Fisher–Yates and 0–15-byte gaps. Copy and repair each selected unit once in anonymous RW scratch.
5. Repair fixed data/dynamic symbols/relocations; rebuild the unwind lookup table using retained frames and update its entry count.
6. Restore original data permissions; make scratch RX; mremap(MAYMOVE|FIXED) replaces the original code pool. Complete unused tail pages become PROT_NONE. No RWX mapping is requested.

Excluded units are never copied into the generated pool. Their translated addresses point into a permanent guard span, with enough room for their within-unit offsets. The whole original pool is replaced, not overlaid with a partial copy. Selected instructions still use repaired direct branches or normal GOT/PLT dispatch; no per-call policy trampoline is added.

Original instructions before/after the pool in partial boundary pages are preserved. Gaps use INT3. Unused complete pages are not populated. Bootstrap remains file-backed RX outside replacement pages. Kernel entropy/mprotect/mremap failure is fatal, not a fixed-layout fallback. Build-tree ld permits missing metadata only to build glibc; final export sets fg_metadata_required = 1.

A small separate anonymous state stores the retained-unit bitmap for late dlopen import checks. The loader never extends that bitmap. It frees state when its object is unmapped. Metadata is advised away with MADV_DONTNEED after generation; late checks can refault its read-only name index. Advice failure only changes residency.

There is no automatic signal pager or full-library compatibility drain. Missing functions stay absent from generated code.

## Boundaries

Disk libraries keep their original code; only this process's code mapping changes. The original final BSS tail is zero-backed in the export to preserve interpreter mapping compatibility. Companion libraries, application functions, PLT stubs and within-function basic-block order are not randomized.

Disk debug symbols/build IDs describe the original layout. Live dynamic symbols and repaired unwind tables describe generated entries. The fixed `_dl_debug_state` rendezvous stays in the bootstrap. `../debug/gdb_fgkaslr.py` reconstructs function destinations from live relocation anchors, creates temporary GDB ELF views with corrected static/dynamic symbols and live unwind sections, and excludes forbidden functions. It suppresses original external DWARF rather than presenting stale source lines. IFUNCs are exposed as ordinary resolver functions in the debugger view; no resolver is invoked by repair. Default symbol versions retain canonical names; compatibility versions get explicit `__fg_compat_` labels. The loader is registered before libc to preserve public-symbol precedence over ld's same-named internal helpers. Original files remain untouched; symbol repair reads, but does not write, inferior memory. This repairs function-level symbol lookup/breakpoints/backtraces, not complete DWARF line tables or variable locations. Anonymous RX code has no original filename in `/proc/maps`.
