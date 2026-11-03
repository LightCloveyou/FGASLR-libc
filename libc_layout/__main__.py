import argparse
import json
import subprocess
import sys
from pathlib import Path

from .build import build, doctor
from .core import audit_records, compare_binaries, inspect_binary, save_json


def main():
    p = argparse.ArgumentParser(description="x86-64 glibc source processor with native ld function randomization")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check local toolchain")
    b = sub.add_parser("build", help="build a libc/ld pair from a local glibc source tree")
    b.add_argument("--source", required=True)
    b.add_argument("--out", required=True, help="fresh non-existing output directory")
    b.add_argument("--seed", help="64 hex digits; defaults to OS-generated 256-bit seed")
    b.add_argument("--patch", action="append", default=[], help="apply a source patch with -p1; repeat in desired order")
    b.add_argument("--jobs", type=int, default=4)
    b.add_argument("--native", action="store_true", help="patch ld/libc sources and export a self-contained per-start randomized pair")
    b.add_argument("--strict", action="store_true", help="reject all compiled grouped, pinned or unknown code units")
    b.add_argument("--skip-check", action="store_true", help="explicitly skip upstream make check")
    i = sub.add_parser("inspect", help="inspect unstripped x86-64 ELF")
    i.add_argument("elf")
    i.add_argument("--json")
    a = sub.add_parser("audit", help="audit compile-time code coverage")
    a.add_argument("records")
    a.add_argument("--strict", action="store_true")
    a.add_argument("--json")
    c = sub.add_parser("compare", help="detect changes to relative function order, independent of ASLR")
    c.add_argument("first")
    c.add_argument("second")
    c.add_argument("--require-diversified", action="store_true")
    c.add_argument("--json")
    args = p.parse_args()
    try:
        if args.command == "build":
            build(args)
            return 0
        if args.command == "doctor":
            result = doctor()
        elif args.command == "inspect":
            result = inspect_binary(args.elf)
        elif args.command == "audit":
            result = audit_records(args.records)
        else:
            result = compare_binaries(args.first, args.second)
        if getattr(args, "json", None):
            save_json(Path(args.json), result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if args.command == "doctor" and not result["ready"]:
            return 2
        if args.command == "audit" and args.strict and not result["strict_pass"]:
            return 2
        if args.command == "compare" and args.require_diversified and not result["layout_diversified"]:
            return 2
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as e:
        print(f"libc-layout: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
