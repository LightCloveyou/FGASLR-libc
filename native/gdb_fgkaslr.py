"""Compatibility entry point for existing .gdbinit files (0BSD).

The implementation lives in debug/gdb_fgkaslr.py. Keep this standalone so
existing GDB source commands do not depend on Python package installation.
"""

from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).resolve().parent / "debug/gdb_fgkaslr.py"))
