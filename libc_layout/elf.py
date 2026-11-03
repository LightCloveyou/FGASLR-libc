"""Small, bounds-checked reader for little-endian ELF64/x86-64."""
import struct
from pathlib import Path


class ELF:
    def __init__(self, path, data=None):
        self.path = Path(path)
        self.data = self.path.read_bytes() if data is None else data
        if self.data[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError(f"{path}: expected little-endian ELF64")
        h = self.unpack("<HHIQQQIHHHHHH", 16)
        self.type, self.machine = h[:2]
        if self.machine != 62:
            raise ValueError(f"{path}: only x86-64 is supported")
        self.entry = h[3]
        phoff, shoff = h[4:6]
        phsize, phnum, shsize, shnum, shstr = h[8:13]
        if shsize != 64 or not shnum or shstr >= shnum:
            raise ValueError(f"{path}: stripped/extended section numbering unsupported")
        self.sections = []
        for i in range(shnum):
            s = self.unpack("<IIQQQQIIQQ", shoff + i * shsize)
            self.sections.append(dict(zip(
                ("name_offset", "type", "flags", "addr", "offset", "size",
                 "link", "info", "align", "entsize"), s), index=i))
        names = self.section_data(self.sections[shstr])
        for s in self.sections:
            s["name"] = self.string(names, s["name_offset"])
        self.segments = []
        if phnum and phsize != 56:
            raise ValueError("unsupported program header size")
        for i in range(phnum):
            p = self.unpack("<IIQQQQQQ", phoff + i * phsize)
            self.segments.append(dict(zip(
                ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align"), p)))

    def unpack(self, fmt, offset):
        n = struct.calcsize(fmt)
        if offset < 0 or offset + n > len(self.data):
            raise ValueError("truncated ELF structure")
        return struct.unpack_from(fmt, self.data, offset)

    @staticmethod
    def string(data, offset):
        if not 0 <= offset < len(data):
            raise ValueError("invalid ELF string offset")
        end = data.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated ELF string")
        return data[offset:end].decode("utf-8", errors="strict")

    def section_data(self, s):
        end = s["offset"] + s["size"]
        if end > len(self.data):
            raise ValueError("truncated ELF section")
        return self.data[s["offset"]:end]

    def symbols(self, dynamic=False):
        result = []
        for s in self.sections:
            if s["type"] != (11 if dynamic else 2):
                continue
            if s["entsize"] != 24 or s["size"] % 24:
                raise ValueError("unsupported ELF symbol size")
            if s["link"] >= len(self.sections):
                raise ValueError("invalid ELF symbol string table")
            strings = self.section_data(self.sections[s["link"]])
            for off in range(s["offset"], s["offset"] + s["size"], 24):
                name, info, other, ndx, value, size = self.unpack("<IBBHQQ", off)
                result.append(dict(name=self.string(strings, name), type=info & 15,
                                   bind=info >> 4, visibility=other & 3,
                                   section=ndx, value=value, size=size))
        return result

    def functions(self):
        return [s for s in self.symbols() if s["type"] in (2, 10) and s["section"] != 0]
