import json
import os
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .core import (
    audit_records,
    inspect_binary,
    map_order,
    normalize_seed,
    save_json,
    sha256,
)

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = (
    "gcc",
    "g++",
    "ld",
    "objcopy",
    "objdump",
    "readelf",
    "nm",
    "ar",
    "make",
    "bison",
    "gawk",
)


def doctor():
    tools = {name: shutil.which(name) for name in REQUIRED}
    ld_version = (
        subprocess.check_output([tools["ld"], "--version"], text=True).splitlines()[0]
        if tools["ld"]
        else ""
    )
    return dict(
        architecture=platform.machine(),
        python=sys.version.split()[0],
        tools=tools,
        linker=ld_version,
        missing=[name for name, path in tools.items() if not path],
        ready=all(tools.values())
        and platform.machine() == "x86_64"
        and "GNU ld" in ld_version,
        note="Also requires Linux kernel headers and a complete local glibc source tree; configure performs version checks.",
    )


def make_wrappers(directory, config):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    config_path = directory / "config.json"
    save_json(config_path, config)
    for mode in ("cc", "ld"):
        wrapper = directory / ("fg" + mode)
        # All launchers are generated from JSON/Python literals, never shell interpolation.
        wrapper.write_text(
            "#!"
            + sys.executable
            + "\nimport sys\nsys.path.insert(0, "
            + repr(str(ROOT))
            + ")\n"
            "from libc_layout.wrapper import main\n"
            "sys.argv[1:1] = " + repr([str(config_path), mode]) + "\n"
            "sys.exit(main())\n"
        )
        wrapper.chmod(0o755)
    return directory / "fgcc", directory / "fgld"


def command(args, cwd, env, log):
    print("+ " + shlex.join(map(str, args)), flush=True)
    with open(log, "a") as f:
        f.write("\n$ " + shlex.join(map(str, args)) + "\n")
        f.flush()
        result = subprocess.run(
            list(map(str, args)), cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT
        )
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); inspect {log}")


def build(args):
    status = doctor()
    if not status["ready"]:
        raise ValueError(
            "build prerequisites unavailable: " + json.dumps(status, ensure_ascii=False)
        )
    source, out = Path(args.source).resolve(), Path(args.out).resolve()
    for path in (source, out, ROOT, Path(sys.executable)):
        if not re.fullmatch(r"/[A-Za-z0-9_./+\-]+", str(path)):
            raise ValueError(
                "build/source/tool paths must use simple ASCII paths without spaces or Make metacharacters"
            )
    if not all(
        (source / f).is_file()
        for f in ("configure", "version.h", "Makerules", "elf/rtld.c")
    ):
        raise ValueError("not a complete glibc source tree")
    if out == source or source in out.parents or out in source.parents:
        raise ValueError("output and source must be separate non-nested directories")
    if out.exists():
        raise ValueError(
            "output directory must not already exist; use a fresh directory for every build"
        )
    if args.jobs < 1:
        raise ValueError("jobs must be positive")
    seed = normalize_seed(args.seed) if args.seed else secrets.token_hex(32)
    # Preserve input sources; upstream build systems can write into their source tree.
    out.mkdir(parents=True)
    private_source, obj = out / "source", out / "build"
    shutil.copytree(
        source, private_source, symlinks=True, ignore=shutil.ignore_patterns(".git")
    )
    obj.mkdir()
    inputs = []
    for p in sorted(private_source.rglob("*")):
        if p.is_symlink():
            if not p.resolve().is_relative_to(private_source):
                raise ValueError(f"external source symlink unsupported: {p}")
            inputs.append(
                dict(path=str(p.relative_to(private_source)), symlink=os.readlink(p))
            )
        elif p.is_file():
            inputs.append(
                dict(path=str(p.relative_to(private_source)), sha256=sha256(p))
            )
    save_json(out / "source-inputs.json", inputs)
    patch_records = []
    native = getattr(args, "native", False)
    if native:
        command(
            [sys.executable, ROOT / "native/tools/patch_glibc.py", private_source],
            private_source,
            os.environ.copy(),
            out / "native-source.log",
        )
        patch_records.append(
            dict(
                native_source_processor=sha256(ROOT / "native/tools/patch_glibc.py"),
                native_engine=sha256(ROOT / "native/runtime/dl-fgkaslr.c"),
                native_policy={
                    name: sha256(ROOT / "native/runtime" / name)
                    for name in ("dl-fg-policy.c", "dl-fg-policy.h", "dl-fg-policy.inc")
                },
            )
        )
    if args.patch and not shutil.which("patch"):
        raise ValueError("--patch requires GNU patch")
    for index, patch in enumerate(args.patch):
        original = Path(patch).resolve()
        saved = out / "patches" / f"{index:03d}.patch"
        saved.parent.mkdir(exist_ok=True)
        shutil.copy2(original, saved)
        command(
            ["patch", "--batch", "--forward", "-p1", "-i", saved],
            private_source,
            os.environ.copy(),
            out / "patch.log",
        )
        patch_records.append(dict(order=index, sha256=sha256(saved)))
    cfg = dict(
        seed=seed,
        build=str(obj),
        records=str(out / "records"),
        cc=status["tools"]["gcc"],
        ld=status["tools"]["ld"],
        objcopy=status["tools"]["objcopy"],
        runtime_metadata=native,
        native=native,
    )
    cc, ld = make_wrappers(out / "toolchain", cfg)
    env = os.environ.copy()
    for name in (
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "CFLAGS",
        "CPPFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "CONFIG_SITE",
        "MAKEFLAGS",
        "MFLAGS",
    ):
        env.pop(name, None)
    env.update(LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="1700000000")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    flags = (
        f"-O2 -g -ffile-prefix-map={private_source}=/fg/source "
        f"-ffile-prefix-map={obj}=/fg/build"
    )
    versions = {
        k: subprocess.check_output([v, "--version"], text=True).splitlines()[0]
        for k, v in status["tools"].items()
    }
    manifest = dict(
        seed=seed,
        source_version=(private_source / "version.h").read_text(),
        tools=versions,
        source_inputs_sha256=sha256(out / "source-inputs.json"),
        patches=patch_records,
        randomization=(
            "native ld per-start function permutation"
            if native
            else "build-time code-section permutation"
        ),
        full_random=False,
        upstream_check="not run",
        state="building",
    )
    save_json(out / "manifest.json", manifest)
    # Configure with the real compiler; wrappers are confined to the subsequent build.
    command(
        [
            private_source / "configure",
            "--prefix=/usr",
            "--disable-werror",
            "--enable-bind-now",
            "CC=" + cfg["cc"],
            "CFLAGS=" + flags,
        ],
        obj,
        env,
        out / "configure.log",
    )
    overrides = ["CC=" + str(cc), "LD=" + str(ld)]
    command(["make", f"-j{args.jobs}", *overrides], obj, env, out / "build.log")
    all_audit = audit_records(out / "records")
    save_json(out / "coverage.json", all_audit)
    binary_reports = {}
    for name, binary in (("libc", obj / "libc.so"), ("ld", obj / "elf/ld.so")):
        mp = Path(str(binary) + ".fg.map")
        if not mp.exists() and name == "ld":
            mp = obj / "elf/ld.so.new.fg.map"
        rows = map_order(mp)
        report = inspect_binary(binary)
        if (
            report["elf_type"] != 3
            or report["wx_segments"]
            or report["executable_stack"]
            or report["text_relocations"]
        ):
            raise ValueError(
                f"{binary}: invalid shared ELF or unsafe memory permissions/relocations"
            )
        report["randomized_units"] = len(rows)
        report["randomized_bytes"] = sum(row[2] for row in rows)
        report["mapped_coverage"] = audit_records(
            out / "records", {row[0] for row in rows}
        )
        save_json(out / (name + "-audit.json"), report)
        binary_reports[name] = dict(sha256=report["sha256"], randomized_units=len(rows))
    manifest["binaries"] = binary_reports
    save_json(out / "manifest.json", manifest)
    if args.strict and not all_audit["strict_pass"]:
        raise ValueError(
            "strict coverage rejected grouped/pinned/unknown code; see coverage.json. No pair exported."
        )
    if not args.skip_check:
        command(
            ["make", f"-j{args.jobs}", *overrides, "check"], obj, env, out / "check.log"
        )
        manifest["upstream_check"] = (
            "passed (inspect test summary for unsupported tests)"
        )
    else:
        manifest["upstream_check"] = "SKIPPED by explicit option; experimental pair"
    pair = out / "pair"
    pair.mkdir()
    if native:
        from native.tools.export_pair import (
            export_native_image,
            export_companion_libraries,
        )

        native_reports = out / "native-reports"
        native_reports.mkdir()
        for image, name in [
            (obj / "libc.so", "libc.so.6"),
            (obj / "elf/ld.so", "ld-linux-x86-64.so.2"),
        ]:
            mp = Path(str(image) + ".fg.map")
            if not mp.exists():
                mp = obj / "elf/ld.so.new.fg.map"
            export_native_image(
                image,
                mp,
                out / "records",
                pair / name,
                native_reports / (name + ".json"),
            )
        export_companion_libraries(obj, pair)
        manifest["native_validation"] = (
            "not run; source-only distribution excludes runtime test fixtures"
        )
    else:
        shutil.copy2(obj / "libc.so", pair / "libc.so.6")
        shutil.copy2(obj / "elf/ld.so", pair / "ld-linux-x86-64.so.2")
    for p in pair.iterdir():
        p.chmod(0o755)
    manifest["state"] = "exported"
    save_json(out / "manifest.json", manifest)
    shutil.copy2(out / "manifest.json", pair / "manifest.json")
    print(
        json.dumps(
            dict(pair=str(pair), seed=seed, manifest=str(out / "manifest.json")),
            indent=2,
        )
    )
