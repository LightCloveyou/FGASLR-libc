"""Apply native loader and assembly entry changes to a private glibc 2.43 tree."""

import argparse
import re
import shutil
from pathlib import Path


def replace_unique(path, old, new):
    """Replace exactly one source anchor, accepting an already-patched file."""
    text = path.read_text()
    if new in text:
        return
    if text.count(old) != 1:
        raise ValueError(f"unexpected glibc source: {path}: {old!r}")
    path.write_text(text.replace(old, new))


def apply_glibc_patches(source):
    """Patch a private glibc 2.43 source tree; original inputs stay untouched."""
    src = Path(source).resolve()
    runtime = Path(__file__).resolve().parents[1] / "runtime"
    shutil.copyfile(runtime / "dl-fgkaslr.c", src / "elf/dl-fgkaslr.c")
    for name in ["dl-fg-policy.c", "dl-fg-policy.h", "dl-fg-policy.inc"]:
        shutil.copyfile(runtime / name, src / "elf" / name)
    # GDB may plant this protocol breakpoint before _fg_start executes. Never
    # copy that byte into the permutation pool or reuse its original location.
    replace_unique(
        src / "elf/dl-debug_state.c",
        "void\n_dl_debug_state (void)",
        "#if defined SHARED && defined __x86_64__ && !defined __ILP32__\n"
        '__attribute__ ((section (".fgboot"), noinline))\n'
        "#endif\nvoid\n_dl_debug_state (void)",
    )
    replace_unique(
        src / "elf/Makefile",
        "rtld-routines = \\\n",
        "rtld-routines = \\\n  dl-fgkaslr \\\n  dl-fg-policy \\\n",
    )
    replace_unique(
        src / "elf/Makefile",
        "CFLAGS-dl-runtime.c +=",
        "CFLAGS-dl-fgkaslr.c += -ffreestanding -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-toplevel-reorder\n\nCFLAGS-dl-runtime.c +=",
    )
    replace_unique(
        src / "elf/Makefile",
        "CFLAGS-dl-runtime.c += -fexceptions -fasynchronous-unwind-tables",
        "CFLAGS-dl-runtime.c += -fexceptions -fasynchronous-unwind-tables\n\n"
        "CFLAGS-dl-debug_state.c += -fno-asynchronous-unwind-tables -fno-unwind-tables",
    )
    # Move libc permutation to dependency completion, still before relocation.
    # All DT_NEEDED objects are available there for native import-root selection.
    load_text = (src / "elf/dl-load.c").read_text()
    if load_text.count("_dl_fg_object (l->l_addr);") > 1:
        raise ValueError("duplicate native object hook in dl-load.c")
    if "_dl_fg_object (l->l_addr);" in load_text:
        raise ValueError("use a fresh source tree; old map-time hook is present")
    replace_unique(
        src / "include/link.h",
        "    ElfW(Addr) l_map_start, l_map_end;",
        "    ElfW(Addr) l_map_start, l_map_end;\n"
        "    void *l_fg_state;\n    unsigned int l_fg_done;",
    )
    replace_unique(
        src / "elf/dl-deps.c",
        "  if (errno_reason)\n",
        "#if defined SHARED && defined __x86_64__ && !defined __ILP32__\n"
        "  if (!errno_reason)\n    {\n"
        "      extern void _dl_fg_apply_maps (struct link_map *) attribute_hidden;\n"
        "      _dl_fg_apply_maps (map);\n    }\n#endif\n\n  if (errno_reason)\n",
    )
    replace_unique(
        src / "elf/dl-unmap-segments.h",
        "_dl_unmap_segments (struct link_map *l)\n{",
        "_dl_unmap_segments (struct link_map *l)\n{\n"
        "#if defined SHARED && defined __x86_64__ && !defined __ILP32__\n"
        "  extern void _dl_fg_unmap (struct link_map *) attribute_hidden;\n"
        "  _dl_fg_unmap (l);\n#endif",
    )
    replace_unique(
        src / "elf/Versions",
        "    __libc_enable_secure;",
        "    __libc_enable_secure;\n    _dl_fg_policy_v1;",
    )
    machine = src / "sysdeps/x86_64/dl-machine.h"
    replace_unique(
        src / "elf/rtld.c",
        "  if (*user_entry == (ElfW(Addr)) ENTRY_POINT)",
        "  extern void _fg_start (void) attribute_hidden;\n"
        "  if (*user_entry == (ElfW(Addr)) _fg_start)",
    )
    replace_unique(
        machine,
        '#define RTLD_START asm ("\\n\\\n',
        '#define RTLD_START asm ("\\n\\\n'
        '.pushsection .fgboot,\\"ax\\",@progbits\\n\\\n'
        ".globl _fg_start\\n\\\n"
        ".hidden _fg_start\\n\\\n"
        ".type _fg_start,@function\\n\\\n"
        "_fg_start:\\n\\\n"
        "  endbr64\\n\\\n"
        "  lea __ehdr_start(%rip),%rdi\\n\\\n"
        "  lea _start(%rip),%rsi\\n\\\n"
        "  call _dl_fg_boot\\n\\\n"
        "  jmp *%rax\\n\\\n"
        ".size _fg_start,.-_fg_start\\n\\\n"
        ".popsection\\n\\\n",
    )
    # The preceding function may fall through to this entry (e.g. _chk stubs).
    # An explicit branch preserves that edge when as emits independent sections.
    header = src / "sysdeps/x86_64/sysdep.h"
    replace_unique(
        header,
        "/* Define an entry point visible from C.  */",
        """/* Native FGKASLR: preserve fallthrough while separating assembly entries. */
#ifdef FG_FUNCTION_SECTIONS
# define FG_ASM_ENTRY(name) \\
  jmp C_SYMBOL_NAME(name); \\
  .section .text.fgfunc.name,"ax",@progbits;
#else
# define FG_ASM_ENTRY(name)
#endif

/* Define an entry point visible from C.  */""",
    )
    replace_unique(
        header,
        "  .globl C_SYMBOL_NAME(name);",
        "  FG_ASM_ENTRY(name) \\\n  .globl C_SYMBOL_NAME(name);",
    )

    # Compat C functions used an explicit shared .text.compat attribute, which
    # overrides -ffunction-sections. Keep symbol versioning, remove only grouping.
    for file in [
        "nptl/cleanup_defer_compat.c",
        "posix/streams-compat.c",
        "misc/regexp.c",
        "nss/compat-lookup.c",
        "signal/sigsetops.c",
    ]:
        path = src / file
        path.write_text(
            path.read_text().replace(
                "attribute_compat_text_section",
                "/* independent compat function section */",
            )
        )
    # speed.c comes from the Linux implementation rather than termios/speed.c.
    for path in (src / "sysdeps").rglob("speed.c"):
        if "attribute_compat_text_section" in path.read_text():
            path.write_text(
                path.read_text().replace(
                    "attribute_compat_text_section",
                    "/* independent compat function section */",
                )
            )
    # strcmp's locale variants deliberately fall through to a second entry.
    for file in ["strcmp-avx2.S", "strcmp-evex.S", "strcmp-sse4_2.S"]:
        path = src / "sysdeps/x86_64/multiarch" / file
        text = path.read_text()
        marker = "\n#ifdef FG_FUNCTION_SECTIONS\n\tFG_ASM_ENTRY(STRCMP)\n#endif\n"
        if marker not in text:
            text, n = re.subn(r"(?m)^STRCMP:", lambda m: marker + m[0], text)
            if n != 1:
                raise ValueError("unrecognized strcmp entry " + file)
            path.write_text(text)
    # These rtld resolvers declare symbols manually instead of using ENTRY.
    for file, names in {
        "dl-trampoline.h": ["_dl_runtime_resolve", "_dl_runtime_profile"],
        "dl-tlsdesc-dynamic.h": ["_dl_tlsdesc_dynamic"],
        "dl-tlsdesc.S": ["_dl_tlsdesc_return", "_dl_tlsdesc_undefweak"],
    }.items():
        path = src / "sysdeps/x86_64" / file
        text = path.read_text()
        for name in names:
            pat = r"(?m)^([ \t]*\.type[ \t]+" + name + r",[ \t]*@function)"
            marker = (
                "\n#ifdef FG_FUNCTION_SECTIONS\n\tFG_ASM_ENTRY(" + name + ")\n#endif\n"
            )
            if marker not in text:
                text, n = re.subn(pat, lambda m: marker + m[1], text)
                if n != 1:
                    raise ValueError("unrecognized resolver: " + name)
        path.write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="private glibc 2.43 source tree")
    args = parser.parse_args()
    apply_glibc_patches(args.source)


if __name__ == "__main__":
    main()
