"""Regression tests for native metadata, source patching and build integration."""

import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from libc_layout.elf import ELF
from libc_layout.wrapper import invoke
from native.tools import export_pair
from native.tools.patch_glibc import replace_unique

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "gdb_layout", ROOT / "native/debug/gdb_fgkaslr.py"
)
gdb_layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gdb_layout)


class IndexedPatchTests(unittest.TestCase):
    def setUp(self):
        self.units = [{"start": 100, "size": 20}, {"start": 200, "size": 32}]
        self.starts = [100, 200]
        self.patch = dict(
            value=208, place=104, kind="absolute", bias=7, width=4, signed=True
        )

    def test_absolute_patch_uses_one_based_unit_indices(self):
        result = export_pair.build_indexed_patch(
            104, self.patch, self.units, self.starts
        )
        self.assertEqual(result, (104, 8, 0, 2, 1, 0, 4, 1, 0, 0))

    def test_relative_patch_biases(self):
        for kind, bias in (
            ("pcrel", -111),
            ("symbol_pcrel", -97),
            ("anchored_pcrel", -201),
        ):
            with self.subTest(kind=kind):
                result = export_pair.build_indexed_patch(
                    104, dict(self.patch, kind=kind), self.units, self.starts
                )
                self.assertEqual(result[2], bias & ((1 << 64) - 1))
                self.assertEqual(result[5], 1)

    def test_fixed_patch_has_no_source_unit(self):
        result = export_pair.build_indexed_patch(
            80, dict(self.patch, place=None, value=900), self.units, self.starts
        )
        self.assertEqual(result[1:5], (900, 0, 0, 0))

    def test_rejects_cross_unit_write_and_unsupported_encodings(self):
        for changes in ({"width": 3}, {"kind": "unknown"}, {"place": 118}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                record = dict(self.patch, **changes)
                export_pair.build_indexed_patch(
                    record["place"], record, self.units, self.starts
                )


class MetadataTests(unittest.TestCase):
    def test_file_offset_translation_and_unmapped_offset(self):
        elf = ELF(ROOT / "lib/libc.so.6")
        load = next(p for p in elf.segments if p["type"] == 1)
        self.assertEqual(
            export_pair.file_offset_to_address(elf, load["offset"], 1), load["vaddr"]
        )
        self.assertIsNone(export_pair.file_offset_to_address(elf, len(elf.data), 1))

    def test_materialized_bss_preserves_virtual_layout(self):
        elf = ELF(ROOT / "lib/ld-linux-x86-64.so.2")
        raw, records = export_pair.materialize_bss_tail(elf.data)
        prepared = ELF("prepared", bytes(raw))
        for before, after in zip(elf.segments, prepared.segments):
            self.assertEqual(before["vaddr"], after["vaddr"])
            self.assertEqual(before["memsz"], after["memsz"])
        # Already-prepared libraries have no BSS tail left to materialize.
        again, second_records = export_pair.materialize_bss_tail(raw)
        self.assertEqual(again, raw)
        self.assertEqual(second_records, [])
        self.assertIsInstance(records, list)

    def test_policy_metadata_is_sorted_and_keeps_export_flags(self):
        class FakeElf:
            sections = []

            def symbols(self, dynamic=False):
                return [
                    dict(type=2, section=1, value=208, name="zeta"),
                    dict(type=2, section=1, value=100, name="malloc@@GLIBC_2.2.5"),
                ]

        units = [{"start": 100, "size": 20}, {"start": 200, "size": 32}]
        data = export_pair.build_policy_metadata(FakeElf(), units, [], 0, 208)
        names, roots, strings, size = struct.unpack_from("<4Q", data)
        self.assertEqual((names, roots, size), (2, 2, len(data)))
        self.assertEqual(strings, len(b"malloc\0zeta\0"))
        self.assertEqual(
            struct.unpack_from("<4I", data, 32), (0, 0x80000001, 7, 0x80000002)
        )
        self.assertEqual(struct.unpack_from("<2I", data, 48), (1, 2))
        self.assertEqual(data[56:], b"malloc\0zeta\0")

    def test_failed_export_preserves_previous_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "libc.so.6"
            out.write_bytes(b"previous artifact")
            with patch.object(
                export_pair,
                "_export_staged_image",
                side_effect=ValueError("invalid ELF"),
            ), self.assertRaisesRegex(ValueError, "invalid ELF"):
                export_pair.export_native_image(
                    None, None, None, out, out.with_suffix(".json")
                )
            self.assertEqual(out.read_bytes(), b"previous artifact")
            self.assertEqual(list(Path(directory).iterdir()), [out])


class SourcePatchTests(unittest.TestCase):
    def test_unique_replacement_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.c"
            path.write_text("old entry")
            replace_unique(path, "old entry", "new entry")
            replace_unique(path, "old entry", "new entry")
            self.assertEqual(path.read_text(), "new entry")

    def test_duplicate_or_missing_anchor_is_rejected_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.c"
            for text in ("old old", "missing"):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    replace_unique(path, "old", "new")
                self.assertEqual(path.read_text(), text)

    def test_wrapper_uses_existing_linker_assets_and_original_entry_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            config = directory / "config.json"
            config.write_text(json.dumps(dict(native=True, ld="ld", cc="gcc")))
            with patch("libc_layout.wrapper.subprocess.run") as run:
                run.return_value.returncode = 0
                result = invoke(config, "ld", ["-o", str(directory / "ld.so")])
            self.assertEqual(result, 0)
            assembly_call, link_call = [call.args[0] for call in run.call_args_list]
            self.assertTrue(Path(assembly_call[2]).is_file())
            self.assertEqual(Path(assembly_call[2]).name, "code_capacity.S")
            script = Path(link_call[link_call.index("-T") + 1])
            self.assertTrue(script.is_file())
            self.assertEqual(script.name, "bootstrap.ld")
            self.assertEqual(link_call[-2:], ["-e", "_fg_start"])


class DebuggerHelperTests(unittest.TestCase):
    def test_mapping_parser_preserves_guard_and_executable_ranges(self):
        maps = gdb_layout.parse_process_mappings(
            "0x1000 0x2000 0x1000 0x0 r-xp /tmp/libc.so.6\n"
            "0x2000 0x3000 0x1000 0x0 ---p\n"
        )
        self.assertEqual(len(maps), 2)
        self.assertTrue(gdb_layout.is_executable_range(maps, 0x1000, 0x1000))
        self.assertFalse(gdb_layout.is_executable_range(maps, 0x1FFF, 2))
        self.assertFalse(gdb_layout.is_executable_range(maps, 0x2000))

    def test_unit_lookup_checks_exclusive_end(self):
        starts, units = [100, 200], [(100, 20), (200, 32)]
        for address, expected in (
            (99, None),
            (100, 0),
            (119, 0),
            (120, None),
            (231, 1),
            (232, None),
        ):
            with self.subTest(address=address):
                self.assertEqual(
                    gdb_layout.find_code_unit(starts, units, address), expected
                )

    def test_mapping_parser_rejects_missing_permissions(self):
        with self.assertRaises(ValueError):
            gdb_layout.parse_process_mappings("no mappings")

    def test_elf_reader_is_standalone_and_bounds_checked(self):
        elf = gdb_layout.ElfImage(ROOT / "lib/libc.so.6")
        self.assertTrue(elf.sections)
        with self.assertRaises(ValueError):
            elf.unpack("<Q", len(elf.data))
        with self.assertRaises(ValueError):
            elf.string(b"unterminated", 0)


if __name__ == "__main__":
    unittest.main()
