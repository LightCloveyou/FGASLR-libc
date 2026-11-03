"""Compiler/linker interposition used only inside an isolated glibc build."""

import json
import subprocess
import sys
from pathlib import Path

from .core import rewrite_object


def output_path(args):
    for i, arg in enumerate(args):
        if arg == "-o" and i + 1 < len(args):
            return Path(args[i + 1]).resolve()
        if arg.startswith("-o") and len(arg) > 2:
            return Path(arg[2:]).resolve()
    return None


def invoke(config_path, mode, args):
    cfg = json.loads(Path(config_path).read_text())
    if any(a.startswith("@") for a in args):
        raise ValueError("response files are unsupported: expand arguments explicitly")
    output = output_path(args)
    extra = []
    compile_object = (
        mode == "cc" and "-c" in args and "-E" not in args and "-S" not in args
    )
    if compile_object:
        if output is None:
            raise ValueError("object compilation requires an explicit -o path")
        output.relative_to(Path(cfg["build"]).resolve())
        extra = [
            "-ffunction-sections",
            "-fno-ipa-icf",
            "-fno-lto",
            "-fno-reorder-blocks-and-partition",
        ]
        if cfg.get("runtime_metadata"):
            extra.extend(["-fno-jump-tables", "-fno-tree-switch-conversion"])
        if cfg.get("native"):
            extra.append("-DFG_FUNCTION_SECTIONS=1")
            # Remove compiler-selected performance alignment at code generation,
            # not by pretending that existing aligned assembly is unaligned.
            if any(a.endswith(".c") for a in args):
                extra.extend(
                    [
                        "-falign-functions=1",
                        "-falign-jumps=1",
                        "-falign-labels=1",
                        "-falign-loops=1",
                    ]
                )
    link = mode == "ld" or (
        mode == "cc"
        and output is not None
        and not any(a in args for a in ("-c", "-S", "-E"))
    )
    if link:
        extra = ["--sort-section=name"] if mode == "ld" else ["-Wl,--sort-section=name"]
        if output is not None and output.name in ("libc.so", "ld.so", "ld.so.new"):
            map_arg = "-Map=" + str(output) + ".fg.map"
            extra.append(map_arg if mode == "ld" else "-Wl," + map_arg)
            if cfg.get("runtime_metadata"):
                extra.extend(
                    ["--emit-relocs", "--no-relax"]
                    if mode == "ld"
                    else ["-Wl,--emit-relocs,--no-relax"]
                )
            if cfg.get("native"):
                script = str(
                    Path(__file__).resolve().parent.parent
                    / "native/linker/bootstrap.ld"
                )
                space = output.with_name(output.name + ".fgspace.o")
                subprocess.run(
                    [
                        cfg["cc"],
                        "-c",
                        str(Path(script).with_name("code_capacity.S")),
                        "-o",
                        str(space),
                    ],
                    check=True,
                )
                extra.extend(
                    [str(space), "-T", script]
                    if mode == "ld"
                    else [str(space), "-Wl,-T," + script]
                )
                if output.name.startswith("ld.so"):
                    extra.extend(
                        ["-e", "_fg_start"] if mode == "ld" else ["-Wl,-e,_fg_start"]
                    )
    result = subprocess.run([cfg[mode], *args, *extra])
    if result.returncode:
        return result.returncode
    if compile_object:
        rewrite_object(output, cfg)
    return 0


def main():
    try:
        return invoke(sys.argv[1], sys.argv[2], sys.argv[3:])
    except (ValueError, OSError, subprocess.CalledProcessError) as e:
        print(f"libc-layout wrapper: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
