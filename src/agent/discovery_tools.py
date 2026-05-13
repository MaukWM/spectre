"""Multi-binary discovery tools (Phase E3).

The static-analysis tools in `ghidra_tools.py` operate on one Ghidra
cache at a time. To let the agent drop into an arbitrary GameCube ISO
and figure out which binary actually holds the game logic — main DOL,
disc-resident ELFs, REL plug-ins — we expose four extra tools:

- `list_iso_contents`  — read the disc FST, list every file
- `extract_iso`        — copy one file out of the ISO
- `analyze_binary`     — run Ghidra on an extracted file; cache by SHA-1
- `switch_binary`      — point the read tools at a different cache

Each `analyze_binary` call updates the per-Sample "current binary" key
in the Inspect AI store, and every Ghidra read tool resolves the cache
via `state.current_cache_dir` at call time — so a switch / analyze in
the middle of a session takes effect immediately, no re-binding needed.
"""

from __future__ import annotations

from pathlib import Path

from inspect_ai.tool import Tool, tool

from src.agent.state import (
    known_binaries,
    set_current_binary,
)
from src.ghidra import (
    cache_dir_for_sha1,
    extract_iso_file,
    is_executable_candidate,
    list_iso_files,
    run_analysis,
    sha1_of,
)
from src.logging import logger


@tool
def list_iso_contents(iso_path: Path) -> Tool:
    """Build `list_iso_contents` bound to the task's ISO."""

    async def execute() -> str:
        """List every file inside the GameCube disc image.

        Output is sorted by size, descending. Lines starting with `*`
        are likely executables (`.elf`, `.dol`, `.rel`) — strong
        candidates to analyze. Lines starting with ` ` are everything
        else (assets, audio, fonts).

        Returns:
            `size_bytes  path` table, capped at 200 rows.
        """
        try:
            files = list_iso_files(iso_path)
        except (OSError, ValueError) as exc:
            return f"Error reading ISO: {exc}"
        if not files:
            return "(no files in disc filesystem)"
        files = sorted(files, key=lambda f: f.size, reverse=True)
        head = files[:200]
        lines = ["mark    size_bytes  path"]
        for f in head:
            mark = "*" if is_executable_candidate(f.path) else " "
            lines.append(f"  {mark}   {f.size:>10}  {f.path}")
        if len(files) > 200:
            lines.append(f"(showing 200 of {len(files)} files)")
        return "\n".join(lines)

    return execute


@tool
def extract_iso(iso_path: Path, extract_root: Path) -> Tool:
    """Build `extract_iso` bound to the task's ISO + scratch dir."""

    async def execute(path_in_iso: str) -> str:
        """Extract one file from the disc to local disk.

        Subsequent calls with the same `path_in_iso` are no-ops (the
        on-disk file is reused). Use the returned on-disk path with
        `analyze_binary` to start Ghidra analysis.

        Args:
            path_in_iso: Forward-slash path exactly as shown by
                `list_iso_contents` (e.g. `Nightfire.elf` or
                `subdir/foo.rel`).

        Returns:
            On-disk path, byte size, and SHA-1 of the extracted file.
        """
        target = path_in_iso.strip().lstrip("/")
        if not target:
            return "Error: path_in_iso is empty"
        out_path = (extract_root / target).resolve()
        try:
            if not out_path.exists():
                size = extract_iso_file(iso_path, target, out_path)
            else:
                size = out_path.stat().st_size
        except (FileNotFoundError, ValueError, OSError) as exc:
            return f"Extract failed: {exc}"
        sha = sha1_of(out_path)
        logger.info("iso_extract", path=target, size=size, sha1=sha)
        return (
            f"Extracted: {target}\n"
            f"  on-disk:  {out_path}\n"
            f"  size:     {size} bytes\n"
            f"  sha1:     {sha}\n"
            f"Pass the on-disk path to `analyze_binary` to start Ghidra."
        )

    return execute


@tool
def analyze_binary(extract_root: Path) -> Tool:
    """Build `analyze_binary` bound to the task's scratch dir.

    Resolves relative paths against `extract_root` so the agent can
    chain `extract_iso("Nightfire.elf")` → `analyze_binary("Nightfire.elf")`
    without copy-pasting the full path.
    """

    async def execute(path: str) -> str:
        """Run Ghidra auto-analysis on an ELF / DOL / REL. Cache by SHA-1.

        On success, the analyzed binary becomes the "current binary"
        for this Sample: subsequent `entry_points`, `find_function`,
        `decompile`, `find_string`, `callees`, `callers`,
        `rename_function`, `add_note` calls target this binary's cache
        until you call `switch_binary` again.

        Idempotent: if the binary's SHA-1 already has a cache, returns
        immediately without re-analyzing (usually instant).

        Args:
            path: Local filesystem path to the binary. May be relative
                (resolved against the scratch dir used by
                `extract_iso`) or absolute.

        Returns:
            Summary including SHA-1, function count, and cache path.
        """
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = (extract_root / path).resolve()
        else:
            p = p.resolve()
        if not p.exists():
            return f"Binary not found: {p}"
        try:
            result = run_analysis(p)
        except (RuntimeError, FileNotFoundError, OSError) as exc:
            return f"Analysis failed: {exc}"
        set_current_binary(result.sha1, p)
        logger.info(
            "agent_analyze_binary",
            path=str(p),
            sha1=result.sha1,
            functions=result.function_count,
        )
        return (
            f"Analyzed: {p.name}\n"
            f"  sha1:      {result.sha1}\n"
            f"  functions: {result.function_count}\n"
            f"  cache:     {result.cache_dir}\n"
            f"Read tools now target this binary. Use `switch_binary(<sha1>)` "
            f"to flip back later."
        )

    return execute


@tool
def switch_binary() -> Tool:
    """Build `switch_binary` (no closure args — operates purely on store state)."""

    async def execute(sha1: str) -> str:
        """Switch the read tools to a different previously-analyzed binary.

        The Ghidra read tools all consult an in-store "current binary"
        pointer at call time. This tool updates that pointer. No effect
        on `run_gecko` or scoring — those always use the task's pinned
        ISO + savestate.

        Args:
            sha1: 40-char hex SHA-1 of an already-analyzed binary.
                Get this from `analyze_binary` or `extract_iso` output.

        Returns:
            Confirmation, or an error if no cache exists for that SHA-1.
        """
        sha = sha1.strip().lower()
        if len(sha) != 40 or not all(c in "0123456789abcdef" for c in sha):
            return f"Error: {sha1!r} is not a 40-char hex SHA-1."
        cache = cache_dir_for_sha1(sha)
        if not (cache / "functions.json").exists():
            return (
                f"No analysis cache for {sha}. Either the SHA-1 is wrong "
                f"or you haven't run `analyze_binary` on this binary yet."
            )
        set_current_binary(sha)
        source = known_binaries().get(sha, "<see initial inventory>")
        return f"Switched to {sha}\n  source: {source}\n  cache:  {cache}"

    return execute
