"""Read-side of the Ghidra analysis cache.

`src.ghidra.analyze` writes a small set of JSON tables + per-function
decompiled pseudocode. This module is the pure-stdlib read layer used by
agent tools.

File map (under `cache/binaries/<sha1>/`):

- `functions.json`       — [{addr, name, size}, ...]
- `callgraph.json`       — {addr: {callees: [{addr, name}], callers: [addr]}}
- `strings.json`         — [{addr, text, xrefs: [function_addr]}]
- `entry_points.json`    — {entries: [{addr, name}]}
- `decompiled/<addr>.txt`— per-function pseudocode
- `notes.json`           — mutable; `src.ghidra.notes.NotesStore`
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FunctionEntry:
    addr: str   # 8-char lowercase hex, e.g. "80003100"
    name: str
    size: int


@dataclass(frozen=True)
class StringEntry:
    addr: str
    text: str
    xrefs: tuple[str, ...]


@dataclass(frozen=True)
class EntryPoint:
    addr: str
    name: str


@dataclass(frozen=True)
class CallEdge:
    addr: str
    name: str


# ---------------------------------------------------------------------------
# loaders


def _read_json_obj(p: Path) -> dict:
    if not p.exists():
        raise FileNotFoundError(f"missing cache file {p}; run scripts/build_analysis.py")
    obj = json.loads(p.read_text())
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON object at top level of {p}, got {type(obj).__name__}")
    return obj


def load_function_index(cache_dir: Path) -> list[FunctionEntry]:
    raw = _read_json_obj(cache_dir / "functions.json")
    return [
        FunctionEntry(addr=str(e["addr"]).lower(), name=str(e["name"]), size=int(e["size"]))
        for e in raw["functions"]
    ]


def load_callgraph(cache_dir: Path) -> dict[str, dict[str, list]]:
    return _read_json_obj(cache_dir / "callgraph.json")


def load_strings(cache_dir: Path) -> list[StringEntry]:
    raw = _read_json_obj(cache_dir / "strings.json")
    return [
        StringEntry(
            addr=str(e["addr"]).lower(),
            text=str(e["text"]),
            xrefs=tuple(str(x).lower() for x in e.get("xrefs", [])),
        )
        for e in raw["strings"]
    ]


def load_entry_points(cache_dir: Path) -> list[EntryPoint]:
    raw = _read_json_obj(cache_dir / "entry_points.json")
    return [EntryPoint(addr=str(e["addr"]).lower(), name=str(e["name"])) for e in raw["entries"]]


# ---------------------------------------------------------------------------
# helpers


def _normalize_addr(query: str) -> str:
    """Accept '0x80003100' / '80003100' / decimal int as string → 8-char lc hex."""
    s = query.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if s.isdigit() and not all(c in "0123456789abcdef" for c in s):
        return f"{int(s, 10):08x}"
    if all(c in "0123456789abcdef" for c in s):
        return s.rjust(8, "0")
    raise ValueError(f"not an address: {query!r}")


def resolve_function(cache_dir: Path, addr_or_name: str) -> FunctionEntry:
    """Resolve a function reference by address, exact original name, or rename.

    Returns the original `FunctionEntry`. Callers wanting the displayed
    name (with renames applied) should consult `NotesStore.display_name`.
    """
    from src.ghidra.notes import NotesStore  # local to avoid cycle

    entries = load_function_index(cache_dir)
    addr_hex: str | None
    try:
        addr_hex = _normalize_addr(addr_or_name)
    except ValueError:
        addr_hex = None

    if addr_hex is not None:
        for e in entries:
            if e.addr == addr_hex:
                return e

    # Try exact match against original Ghidra names.
    for e in entries:
        if e.name == addr_or_name:
            return e

    # Try renamed names from the sidecar.
    notes = NotesStore.load(cache_dir)
    target = addr_or_name.strip()
    matches = [a for a, n in notes.renames.items() if n == target]
    if len(matches) == 1:
        for e in entries:
            if e.addr == matches[0]:
                return e
    if len(matches) > 1:
        raise KeyError(f"name {addr_or_name!r} ambiguous; matches {matches}")

    raise KeyError(f"no function matches {addr_or_name!r}")


def find_functions(
    cache_dir: Path,
    pattern: str,
    *,
    limit: int = 40,
    case_insensitive: bool = True,
) -> list[FunctionEntry]:
    """Regex over original names AND renames. Returns up to `limit` rows."""
    from src.ghidra.notes import NotesStore

    flags = re.IGNORECASE if case_insensitive else 0
    regex = re.compile(pattern, flags)

    notes = NotesStore.load(cache_dir)
    out: list[FunctionEntry] = []
    for entry in load_function_index(cache_dir):
        display = notes.display_name(entry.addr, entry.name)
        if regex.search(entry.name) or (display != entry.name and regex.search(display)):
            out.append(entry)
            if len(out) >= limit:
                break
    return out


def read_decompiled(cache_dir: Path, addr_or_name: str) -> tuple[FunctionEntry, str]:
    """Resolve a function by address/name/rename, return its pseudocode."""
    entry = resolve_function(cache_dir, addr_or_name)
    decomp_path = cache_dir / "decompiled" / f"{entry.addr}.txt"
    if not decomp_path.exists():
        raise FileNotFoundError(f"decompiled file missing: {decomp_path}")
    return entry, decomp_path.read_text()


def callees_of(cache_dir: Path, addr: str) -> list[CallEdge]:
    cg = load_callgraph(cache_dir)
    raw = cg.get(addr.lower(), {})
    return [
        CallEdge(addr=str(c["addr"]).lower(), name=str(c["name"]))
        for c in raw.get("callees", [])
    ]


def callers_of(cache_dir: Path, addr: str) -> list[CallEdge]:
    """Caller addrs; names are filled in from the function index."""
    cg = load_callgraph(cache_dir)
    raw_addrs = cg.get(addr.lower(), {}).get("callers", [])
    if not raw_addrs:
        return []
    index = {e.addr: e.name for e in load_function_index(cache_dir)}
    return [CallEdge(addr=str(a).lower(), name=index.get(str(a).lower(), "<unknown>")) for a in raw_addrs]


def find_orphan_roots(cache_dir: Path, *, limit: int = 20) -> list[FunctionEntry]:
    """Functions with zero in-callgraph callers, sorted by size descending.

    Ghidra's `ExternalEntryPointIterator` only flags symbol-marked entries —
    typically just `e_entry` on a stripped ELF. Orphan roots fill the gap:
    they're functions that no other function in the binary calls, which
    usually means they're invoked via vtable / interrupt vector / dynamic
    dispatch — or they're the actual program entry that was stripped.
    Sorted by size so big roots (main loops, render dispatchers) come first.
    """
    funcs = load_function_index(cache_dir)
    cg = load_callgraph(cache_dir)
    roots = [f for f in funcs if not cg.get(f.addr, {}).get("callers")]
    roots.sort(key=lambda f: f.size, reverse=True)
    return roots[:limit]


def search_strings(
    cache_dir: Path,
    pattern: str,
    *,
    limit: int = 25,
    case_insensitive: bool = True,
) -> list[StringEntry]:
    flags = re.IGNORECASE if case_insensitive else 0
    regex = re.compile(pattern, flags)
    out: list[StringEntry] = []
    for s in load_strings(cache_dir):
        if regex.search(s.text):
            out.append(s)
            if len(out) >= limit:
                break
    return out
