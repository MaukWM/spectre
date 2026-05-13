"""Shared per-Sample agent state, stored in Inspect AI's `store()`.

Store keys are read + written across tool calls within the same Sample.
Centralising them here keeps tools and the scorer consistent and avoids
typo'd magic strings.

Notable: `CURRENT_BINARY_SHA1_KEY` lets the agent switch which Ghidra
cache the read tools (`find_function`, `decompile`, ...) target during
a session. Tools resolve the active cache lazily via
`current_cache_dir` so a `switch_binary(sha1)` call takes effect for
every subsequent call without re-binding tool closures.
"""

from __future__ import annotations

from pathlib import Path

from inspect_ai.util import store

from src.ghidra.analyze import cache_dir_for_sha1

# `run_gecko` budget counter (int).
BUDGET_KEY = "spectre_run_gecko_used"

# Last gecko_text that earned a PASS verdict (str). The scorer falls back
# to this if the agent forgets to submit a textual answer.
LAST_PASS_KEY = "spectre_last_pass_gecko"

# Current binary SHA-1 the agent is exploring. None / unset → no binary
# selected yet; the agent must call `switch_binary` before any
# static-analysis tool will return data.
CURRENT_BINARY_SHA1_KEY = "spectre_current_binary_sha1"

# Map of {sha1: source_binary_path_str} so `list_known_binaries` can show
# the agent which binaries have already been analyzed this session.
KNOWN_BINARIES_KEY = "spectre_known_binaries"


def set_current_binary(sha1: str, source_path: Path | None = None) -> None:
    """Switch the active binary the read tools target."""
    s = store()
    s.set(CURRENT_BINARY_SHA1_KEY, sha1)
    if source_path is not None:
        known = dict(s.get(KNOWN_BINARIES_KEY, {}) or {})
        known[sha1] = str(source_path)
        s.set(KNOWN_BINARIES_KEY, known)


def current_cache_dir() -> Path | None:
    """Cache dir for the binary the agent has selected, or None.

    Returns None when no `switch_binary` has been called yet. Read tools
    must treat None as "agent needs to pick a binary first" and respond
    with a pointer to the inventory in the initial user message.
    """
    sha1 = store().get(CURRENT_BINARY_SHA1_KEY)
    if isinstance(sha1, str) and sha1:
        return cache_dir_for_sha1(sha1)
    return None


NO_BINARY_SELECTED_MSG = (
    "No binary selected yet. Review the binary inventory in the initial "
    "task description and call `switch_binary(<sha1>)` to pick one before "
    "using the static-analysis tools."
)


def known_binaries() -> dict[str, str]:
    """Snapshot of binaries the agent has analyzed this session."""
    raw: dict[str, str] = store().get(KNOWN_BINARIES_KEY, {}) or {}
    return {str(k): str(v) for k, v in raw.items()}
