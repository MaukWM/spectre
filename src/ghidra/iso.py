"""GameCube disc image (ISO/GCM) reader: FST listing + file extraction.

GameCube format, big-endian:

- `0x0000`  6 bytes  ASCII game ID (e.g. `GO7E69`)
- `0x0420`  u32      `boot.dol` offset on disc
- `0x0424`  u32      File String Table offset
- `0x0428`  u32      FST size

FST is an array of 12-byte entries followed by a name string table.
Entry 0 is the root directory; its `size` field holds the total entry
count (root + every file + every subdir). Each entry is either a file
(byte 0 == 0) or a directory (byte 0 == 1). Names are NUL-terminated
ASCII in the string table that follows the entries.

This is pure-stdlib; no Dolphin / dolphin-tool required.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

_GAME_ID_OFFSET = 0x0000
_DOL_OFFSET_FIELD = 0x0420
_FST_OFFSET_FIELD = 0x0424
_FST_SIZE_FIELD = 0x0428
_ENTRY_SIZE = 12


@dataclass(frozen=True)
class IsoFile:
    """One file entry from the disc FST."""

    path: str         # forward-slash, no leading slash (e.g. "files/Nightfire.elf")
    offset: int       # absolute byte offset within the ISO
    size: int


@dataclass(frozen=True)
class IsoHeader:
    game_id: str
    dol_offset: int
    fst_offset: int
    fst_size: int


def read_header(iso_path: Path) -> IsoHeader:
    """Read the disc header (game ID + DOL/FST offsets)."""
    with iso_path.open("rb") as f:
        f.seek(_GAME_ID_OFFSET)
        game_id = f.read(6).decode("ascii", errors="replace")
        f.seek(_DOL_OFFSET_FIELD)
        dol_off = struct.unpack(">I", f.read(4))[0]
        f.seek(_FST_OFFSET_FIELD)
        fst_off, fst_sz = struct.unpack(">II", f.read(8))
    return IsoHeader(game_id=game_id, dol_offset=dol_off, fst_offset=fst_off, fst_size=fst_sz)


def list_iso_files(iso_path: Path) -> list[IsoFile]:
    """Walk the FST and return every file in the disc filesystem.

    Directories are not returned as their own entries; their paths show
    up as prefixes on contained files. Empty directories are skipped.
    """
    hdr = read_header(iso_path)
    with iso_path.open("rb") as f:
        f.seek(hdr.fst_offset)
        fst = f.read(hdr.fst_size)

    if len(fst) < _ENTRY_SIZE:
        raise ValueError(f"FST truncated: {len(fst)} bytes")

    # Root entry: bytes 8..12 = total entry count.
    entry_count = struct.unpack(">I", fst[8:_ENTRY_SIZE])[0]
    str_table_start = entry_count * _ENTRY_SIZE
    if str_table_start > len(fst):
        raise ValueError(f"FST claims {entry_count} entries but only {len(fst)} bytes")
    str_table = fst[str_table_start:]

    def read_name(name_offset: int) -> str:
        end = str_table.find(b"\x00", name_offset)
        if end < 0:
            end = len(str_table)
        return str_table[name_offset:end].decode("ascii", errors="replace")

    def parse(i: int) -> tuple[bool, int, int, int]:
        base = i * _ENTRY_SIZE
        is_dir = fst[base] == 1
        name_off = int.from_bytes(fst[base + 1 : base + 4], "big")
        a = struct.unpack(">I", fst[base + 4 : base + 8])[0]
        b = struct.unpack(">I", fst[base + 8 : base + 12])[0]
        return is_dir, name_off, a, b

    out: list[IsoFile] = []

    def walk(start: int, end: int, prefix: str) -> None:
        i = start
        while i < end:
            is_dir, name_off, a, b = parse(i)
            name = read_name(name_off)
            path = f"{prefix}{name}"
            if is_dir:
                walk(i + 1, b, f"{path}/")
                i = b
            else:
                out.append(IsoFile(path=path, offset=a, size=b))
                i += 1

    walk(1, entry_count, "")
    return out


def extract_iso_file(iso_path: Path, path_in_iso: str, out_path: Path) -> int:
    """Extract one file from the ISO to `out_path`. Returns bytes written."""
    target = path_in_iso.lstrip("/")
    files = list_iso_files(iso_path)
    match = next((e for e in files if e.path == target), None)
    if match is None:
        raise FileNotFoundError(f"{target!r} not in ISO {iso_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with iso_path.open("rb") as f:
        f.seek(match.offset)
        data = f.read(match.size)
    if len(data) != match.size:
        raise ValueError(f"short read: wanted {match.size}, got {len(data)}")
    out_path.write_bytes(data)
    return len(data)


def is_executable_candidate(name: str) -> bool:
    """Heuristic: file paths that look like analyzable code blobs."""
    low = name.lower()
    return low.endswith((".elf", ".rel", ".dol"))


_EM_PPC = 0x14
_ELF_MAGIC = b"\x7fELF"


def patch_elf_machine_ppc(path: Path) -> bool:
    """If `path` is a stripped-machine ELF, patch e_machine to EM_PPC.

    Eurocom and a few other GameCube publishers ship ELFs inside the
    disc filesystem with `e_machine = EM_NONE (0)`. Ghidra refuses to
    load them — "unsupported binary type". Every GameCube game is
    PowerPC, so when we see EM_NONE on an MSB 32-bit ELF we patch it
    to EM_PPC (`0x14`) in place. Returns True if a patch was applied.
    Mutates the on-disk file; intended only for derived/extracted
    binaries that the caller owns.
    """
    with path.open("r+b") as f:
        head = f.read(20)
        if len(head) < 20 or head[:4] != _ELF_MAGIC:
            return False
        # EI_DATA at offset 5: 2 = big-endian (GameCube/Wii). Skip if not.
        if head[5] != 2:
            return False
        machine = int.from_bytes(head[0x12:0x14], "big")
        if machine != 0:
            return False
        f.seek(0x12)
        f.write(_EM_PPC.to_bytes(2, "big"))
    return True
