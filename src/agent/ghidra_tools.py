"""Inspect AI tools backed by the Ghidra analysis cache.

Tool roster (each is a parameterless `@tool` factory):

- `entry_points()`                     — where to start exploring
- `find_function(pattern, limit)`      — regex over original + renamed names
- `decompile(addr_or_name)`            — pseudocode with renames applied + nav header
- `callees(addr_or_name)`              — functions this one calls
- `callers(addr_or_name)`              — functions that call this one (xrefs)
- `find_string(pattern, limit)`        — strings + functions that reference them
- `rename_function(addr_or_name, ...)` — persist a rename in the sidecar
- `add_note(addr_or_name, text)`       — persist a free-text note in the sidecar

Every tool reads the active binary's cache via `state.current_cache_dir`
at call time. If the agent hasn't called `switch_binary(<sha1>)` yet,
each tool returns the `NO_BINARY_SELECTED_MSG` to nudge the agent to
pick from the inventory in the initial user message. All read tools
cap their output to keep tool results manageable.
"""

from __future__ import annotations

import re

from inspect_ai.tool import Tool, tool

from src.agent.state import NO_BINARY_SELECTED_MSG, current_cache_dir
from src.ghidra import NotesStore
from src.ghidra.cache import (
    callees_of,
    callers_of,
    find_functions,
    find_orphan_roots,
    load_entry_points,
    read_decompiled,
    resolve_function,
    search_strings,
)

_MAX_DECOMP_CHARS = 16_000


def _fmt_func_table(rows: list[tuple[str, str, int]]) -> str:
    if not rows:
        return "(no matches)"
    lines = ["addr      size    name"]
    for addr, name, size in rows:
        lines.append(f"{addr}  {size:6d}  {name}")
    return "\n".join(lines)


def _fmt_edge_table(rows: list[tuple[str, str]]) -> str:
    if not rows:
        return "(none)"
    lines = ["addr      name"]
    for addr, name in rows:
        lines.append(f"{addr}  {name}")
    return "\n".join(lines)


def _apply_renames_to_body(text: str, renames: dict[str, str]) -> str:
    """Replace `FUN_xxxxxxxx` / `DAT_xxxxxxxx` references with renames."""
    if not renames:
        return text

    pat = re.compile(r"(FUN|DAT|LAB|PTR|UNK)_([0-9a-fA-F]{8})\b")

    def sub(m: re.Match[str]) -> str:
        addr_hex = m.group(2).lower()
        if addr_hex in renames:
            return renames[addr_hex]
        return m.group(0)

    return pat.sub(sub, text)


# ---------------------------------------------------------------------------
# read tools


@tool
def entry_points() -> Tool:
    """Build the `entry_points` tool."""

    async def execute() -> str:
        """List the active binary's entry points — start exploration here.

        Returns two sections:

        1. **Marked entries** — addresses Ghidra's loader flagged as
           external entry points (usually just `e_entry` on stripped
           ELFs / the DOL bootstrap).
        2. **Orphan roots** — functions with zero in-callgraph callers,
           sorted by size descending. These are reached via vtable /
           interrupt vector / dynamic dispatch (or are stripped real
           entries), so they're strong starting candidates when the
           binary has only one marked entry. Top 20 shown.
        """
        cache_dir = current_cache_dir()
        if cache_dir is None:
            return NO_BINARY_SELECTED_MSG
        try:
            eps = load_entry_points(cache_dir)
        except FileNotFoundError as exc:
            return f"Analysis cache not built: {exc}"
        notes = NotesStore.load(cache_dir)

        marked_rows = [(e.addr, notes.display_name(e.addr, e.name)) for e in eps]
        marked_addrs = {a for a, _ in marked_rows}

        try:
            roots = find_orphan_roots(cache_dir, limit=20)
        except FileNotFoundError:
            roots = []
        root_rows = [
            (r.addr, notes.display_name(r.addr, r.name), r.size)
            for r in roots
            if r.addr not in marked_addrs
        ]

        out = [
            "## Marked entries",
            "Addresses Ghidra's loader flagged as program entry "
            "(`e_entry` on ELFs; bootstrap on DOLs). This is *the* true",
            "execution start. Begin exploration here.",
            "",
            _fmt_edge_table(marked_rows),
        ]
        if root_rows:
            out.extend(
                [
                    "",
                    "## Orphan roots (top 20 by size)",
                    "Functions Ghidra found but with **no in-binary callers**. "
                    "These are reached via vtable / interrupt vector / dynamic",
                    "dispatch / dead code / stripped symbols. They are NOT the "
                    "program entry — they are *secondary* exploration candidates",
                    "alongside the marked entry above. Useful when "
                    "`find_string` doesn't surface a code path.",
                    "",
                    _fmt_func_table(root_rows),
                ]
            )
        return "\n".join(out)

    return execute


@tool
def find_function() -> Tool:
    """Build the `find_function` tool."""

    async def execute(pattern: str, limit: int = 40) -> str:
        """Search the active binary's function table by regex on the name.

        Args:
            pattern: Python `re` pattern. Case-insensitive. Use `.` for all.
            limit: Max rows to return. Default 40.

        Returns:
            Compact `addr  size  name` table, or `(no matches)`.
        """
        cache_dir = current_cache_dir()
        if cache_dir is None:
            return NO_BINARY_SELECTED_MSG
        try:
            results = find_functions(cache_dir, pattern, limit=limit)
        except FileNotFoundError as exc:
            return f"Analysis cache not built: {exc}"
        except re.error as exc:
            return f"Bad regex: {exc}"
        notes = NotesStore.load(cache_dir)
        rows = [(e.addr, notes.display_name(e.addr, e.name), e.size) for e in results]
        return _fmt_func_table(rows)

    return execute


@tool
def decompile() -> Tool:
    """Build the `decompile` tool."""

    async def execute(addr_or_name: str) -> str:
        """Return Ghidra's C-like pseudocode for one function in the active binary.

        Body has your renames substituted (`FUN_xxxxxxxx` → your name).
        Header shows current name, address, size, your note (if any),
        and a compact callees + callers summary. Capped near 16 KB.

        Args:
            addr_or_name: Address (`0x80066548`, `80066548`, decimal) OR
                original name (`FUN_80066548`) OR a name you renamed to.
        """
        cache_dir = current_cache_dir()
        if cache_dir is None:
            return NO_BINARY_SELECTED_MSG
        try:
            entry, code = read_decompiled(cache_dir, addr_or_name)
        except FileNotFoundError as exc:
            return f"Analysis cache not built: {exc}"
        except KeyError as exc:
            return f"No function matches: {exc}"

        notes = NotesStore.load(cache_dir)
        display_name = notes.display_name(entry.addr, entry.name)
        note_text = notes.notes.get(entry.addr)

        try:
            cs = callees_of(cache_dir, entry.addr)
            csr = callers_of(cache_dir, entry.addr)
        except FileNotFoundError:
            cs, csr = [], []

        def _short(edges: list, k: int = 8) -> str:
            if not edges:
                return "(none)"
            head = [f"{notes.display_name(e.addr, e.name)}@0x{e.addr}" for e in edges[:k]]
            tail = "" if len(edges) <= k else f", +{len(edges)-k} more"
            return ", ".join(head) + tail

        header_lines = [
            f"// addr 0x{entry.addr}  size {entry.size}  name {display_name}",
        ]
        if display_name != entry.name:
            header_lines.append(f"// (originally {entry.name})")
        if note_text:
            header_lines.append(f"// note: {note_text}")
        header_lines.append(f"// callees ({len(cs)}): {_short(cs)}")
        header_lines.append(f"// callers ({len(csr)}): {_short(csr)}")
        header = "\n".join(header_lines) + "\n\n"

        body = _apply_renames_to_body(code, notes.renames)
        if len(body) > _MAX_DECOMP_CHARS:
            body = body[:_MAX_DECOMP_CHARS] + f"\n\n// (truncated; full length {len(body)} chars)"
        return header + body

    return execute


@tool
def callees() -> Tool:
    """Build the `callees` tool."""

    async def execute(addr_or_name: str) -> str:
        """Functions called by the given function in the active binary. Walk *outward*.

        Args:
            addr_or_name: Address (e.g. `0x80066548`) OR original name
                (`FUN_80066548`) OR a name you previously assigned via
                `rename_function`.
        """
        cache_dir = current_cache_dir()
        if cache_dir is None:
            return NO_BINARY_SELECTED_MSG
        try:
            entry = resolve_function(cache_dir, addr_or_name)
            edges = callees_of(cache_dir, entry.addr)
        except (FileNotFoundError, KeyError) as exc:
            return f"Error: {exc}"
        notes = NotesStore.load(cache_dir)
        rows = [(e.addr, notes.display_name(e.addr, e.name)) for e in edges]
        return _fmt_edge_table(rows)

    return execute


@tool
def callers() -> Tool:
    """Build the `callers` tool."""

    async def execute(addr_or_name: str) -> str:
        """Functions that call the given function in the active binary. Walk *inward*.

        Args:
            addr_or_name: Address (e.g. `0x80066548`) OR original name
                (`FUN_80066548`) OR a name you previously assigned via
                `rename_function`.
        """
        cache_dir = current_cache_dir()
        if cache_dir is None:
            return NO_BINARY_SELECTED_MSG
        try:
            entry = resolve_function(cache_dir, addr_or_name)
            edges = callers_of(cache_dir, entry.addr)
        except (FileNotFoundError, KeyError) as exc:
            return f"Error: {exc}"
        notes = NotesStore.load(cache_dir)
        rows = [(e.addr, notes.display_name(e.addr, e.name)) for e in edges]
        return _fmt_edge_table(rows)

    return execute


@tool
def find_string() -> Tool:
    """Build the `find_string` tool."""

    async def execute(pattern: str, limit: int = 25) -> str:
        """Regex-search defined strings in the active binary.

        Args:
            pattern: Python `re` pattern. Case-insensitive.
            limit: Max strings to return.

        Returns:
            For each match: `<saddr>  "<text>"\\n    xrefs: <fn1> <fn2> ...`
        """
        cache_dir = current_cache_dir()
        if cache_dir is None:
            return NO_BINARY_SELECTED_MSG
        try:
            results = search_strings(cache_dir, pattern, limit=limit)
        except FileNotFoundError as exc:
            return f"Analysis cache not built: {exc}"
        except re.error as exc:
            return f"Bad regex: {exc}"
        if not results:
            return "(no matches)"
        notes = NotesStore.load(cache_dir)
        out: list[str] = []
        for s in results:
            preview = s.text.replace("\n", "\\n")
            if len(preview) > 80:
                preview = preview[:77] + "..."
            xrefs_disp = " ".join(
                f"{notes.display_name(x, x)}@0x{x}" for x in s.xrefs[:6]
            )
            if len(s.xrefs) > 6:
                xrefs_disp += f" +{len(s.xrefs)-6} more"
            out.append(f"0x{s.addr}  \"{preview}\"\n    xrefs: {xrefs_disp}")
        return "\n".join(out)

    return execute


# ---------------------------------------------------------------------------
# mutating tools


@tool
def rename_function() -> Tool:
    """Build the `rename_function` tool."""

    async def execute(addr_or_name: str, new_name: str) -> str:
        """Persist a rename for a function in the active binary.

        Future `find_function`, `decompile`, `callees`, `callers`, and
        `find_string` outputs will use the new name. Renaming the same
        address again overwrites the prior rename (last write wins).
        Renames are stored per-binary in `cache/binaries/<sha1>/notes.json`.

        Args:
            addr_or_name: How to identify the function to rename.
            new_name: Your new name. Keep it short and code-identifier-shaped.
        """
        if not new_name or not new_name.strip():
            return "Error: new_name is empty."
        cache_dir = current_cache_dir()
        if cache_dir is None:
            return NO_BINARY_SELECTED_MSG
        try:
            entry = resolve_function(cache_dir, addr_or_name)
        except (FileNotFoundError, KeyError) as exc:
            return f"Error: {exc}"
        notes = NotesStore.load(cache_dir)
        prior = notes.renames.get(entry.addr)
        notes.rename(entry.addr, new_name.strip())
        if prior:
            return f"Renamed 0x{entry.addr}: {prior!r} → {new_name.strip()!r}"
        return f"Renamed 0x{entry.addr} ({entry.name}) → {new_name.strip()!r}"

    return execute


@tool
def add_note() -> Tool:
    """Build the `add_note` tool."""

    async def execute(addr_or_name: str, text: str) -> str:
        """Persist a free-text note attached to a function in the active binary.

        Appears in the decompile header on every future call. Overwrites
        any prior note at the same address. Notes are stored per-binary
        in `cache/binaries/<sha1>/notes.json`.

        Args:
            addr_or_name: How to identify the function.
            text: Anything you want to remember — typically a hypothesis
                about what this function does, or what you've ruled out.
        """
        if not text.strip():
            return "Error: text is empty."
        cache_dir = current_cache_dir()
        if cache_dir is None:
            return NO_BINARY_SELECTED_MSG
        try:
            entry = resolve_function(cache_dir, addr_or_name)
        except (FileNotFoundError, KeyError) as exc:
            return f"Error: {exc}"
        notes = NotesStore.load(cache_dir)
        notes.add_note(entry.addr, text.strip())
        return f"Note saved on 0x{entry.addr}: {text.strip()[:80]}"

    return execute
