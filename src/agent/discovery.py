"""Pre-task ISO inventory: extract + Ghidra-analyze every executable.

`survey_and_analyze` is called once at task creation time. It walks the
disc filesystem, extracts every `.elf` / `.dol` / `.rel` to disk, runs
Ghidra on each, and returns one `BinaryCandidate` per analyzed binary.

The agent then sees this inventory in its initial user message and
chooses which binary to explore via `switch_binary(<sha1>)`. No default
is pre-selected: the agent has to look at the menu and decide.

Caching: per-binary analysis is content-addressed under
`cache/binaries/<sha1>/`, so the second run against the same disc skips
straight to "already analyzed" for every entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.ghidra import (
    extract_dol,
    extract_iso_file,
    is_executable_candidate,
    list_iso_files,
    patch_elf_machine_ppc,
    run_analysis,
)
from src.logging import logger


@dataclass(frozen=True)
class BinaryCandidate:
    """One analyzed binary, ready for the agent to switch to."""

    label: str            # display name (path inside ISO, or "boot.dol")
    on_disk_path: Path
    size: int             # bytes on disc
    sha1: str
    function_count: int
    note: str = ""        # optional hint shown alongside in the inventory


def survey_and_analyze(
    iso_path: Path,
    extract_root: Path,
    *,
    extras: list[Path] | None = None,
    on_progress: object | None = None,
    on_detail: object | None = None,
) -> list[BinaryCandidate]:
    """Extract + Ghidra-analyze every executable in the ISO.

    Order of the returned list:
      1. `boot.dol` from the disc header (always present on a valid ISO)
      2. ELF files, sorted by on-disc size desc
      3. REL files, sorted by on-disc size desc (marked experimental)
      4. `extras` — caller-supplied binaries (e.g. an env-supplied ELF
         that already has agent notes from prior runs); these are
         appended last and labelled with the file's basename.

    Eurocom and some other publishers ship ELFs with `e_machine = 0`
    (stripped), which Ghidra refuses to load. We auto-patch extracted
    ELFs to `EM_PPC` before analysis — every GameCube game is PowerPC,
    so the patch is always correct in this domain. Patches are applied
    only to files under `extract_root`, never to caller-supplied paths.

    Any single binary that fails to analyze is logged and skipped; the
    rest still come back. `Exception` is caught broadly because Ghidra
    surfaces `ghidra.app.util.opinion.LoadException` via JPype, which
    doesn't subclass any Python builtin.
    """
    extract_root.mkdir(parents=True, exist_ok=True)
    out: list[BinaryCandidate] = []
    seen_sha: set[str] = set()

    def _progress(done: int, total: int, label: str) -> None:
        if callable(on_progress):
            on_progress(done, total, label)

    # Count total candidates first for progress reporting
    fst_candidates = [f for f in list_iso_files(iso_path) if is_executable_candidate(f.path)]
    total_candidates = 1 + len(fst_candidates) + len(extras or [])  # boot.dol + fst + extras
    analyzed_count = 0

    # Report total upfront so the UI shows "0/N" instead of "0/?"
    _progress(0, total_candidates, "starting...")

    # 1. boot.dol from the ISO header.
    dol_path = extract_root / "boot.dol"
    try:
        if not dol_path.exists():
            extract_dol(iso_path, dol_path)
        res = run_analysis(dol_path, on_detail=on_detail)
        if res.sha1 not in seen_sha:
            seen_sha.add(res.sha1)
            out.append(
                BinaryCandidate(
                    label="boot.dol",
                    on_disk_path=dol_path,
                    size=dol_path.stat().st_size,
                    sha1=res.sha1,
                    function_count=res.function_count,
                    note="bootstrap DOL from ISO header — tiny on REL-based games",
                )
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("survey_dol_failed", error=str(exc))
    analyzed_count += 1
    _progress(analyzed_count, total_candidates, "boot.dol")

    # 2 + 3. Disc-filesystem candidates (already counted above).
    elfs = sorted(
        [f for f in fst_candidates if f.path.lower().endswith((".elf", ".dol"))],
        key=lambda f: f.size,
        reverse=True,
    )
    rels = sorted(
        [f for f in fst_candidates if f.path.lower().endswith(".rel")],
        key=lambda f: f.size,
        reverse=True,
    )

    for f in elfs + rels:
        target = (extract_root / f.path).resolve()
        notes: list[str] = []
        try:
            if not target.exists():
                extract_iso_file(iso_path, f.path, target)
            if target.suffix.lower() == ".elf":
                if patch_elf_machine_ppc(target):
                    logger.info("elf_machine_patched_to_ppc", path=str(target))
                    notes.append("e_machine patched EM_NONE → EM_PPC")
            res = run_analysis(target, on_detail=on_detail)
        except Exception as exc:  # noqa: BLE001
            logger.warning("survey_candidate_failed", path=f.path, error=str(exc))
            analyzed_count += 1
            _progress(analyzed_count, total_candidates, f.path)
            continue
        analyzed_count += 1
        _progress(analyzed_count, total_candidates, f.path)
        if res.sha1 in seen_sha:
            continue
        seen_sha.add(res.sha1)
        if f.path.lower().endswith(".rel"):
            notes.append("REL plug-in — load address unknown; xrefs may be off")
        out.append(
            BinaryCandidate(
                label=f.path,
                on_disk_path=target,
                size=f.size,
                sha1=res.sha1,
                function_count=res.function_count,
                note="; ".join(notes),
            )
        )

    # 4. Extras (e.g. user-supplied env ELF — preserves prior-run notes).
    for p in extras or []:
        p = p.resolve()
        if not p.exists():
            logger.warning("survey_extra_missing", path=str(p))
            continue
        try:
            res = run_analysis(p, on_detail=on_detail)
        except Exception as exc:  # noqa: BLE001
            logger.warning("survey_extra_failed", path=str(p), error=str(exc))
            analyzed_count += 1
            _progress(analyzed_count, total_candidates, p.name)
            continue
        analyzed_count += 1
        _progress(analyzed_count, total_candidates, p.name)
        if res.sha1 in seen_sha:
            continue
        seen_sha.add(res.sha1)
        out.append(
            BinaryCandidate(
                label=p.name,
                on_disk_path=p,
                size=p.stat().st_size,
                sha1=res.sha1,
                function_count=res.function_count,
                note=f"user-supplied (from {p.parent})",
            )
        )

    logger.info("survey_complete", iso=str(iso_path), candidates=len(out))
    return out


def format_inventory(candidates: list[BinaryCandidate]) -> str:
    """Render the binary inventory for the agent's initial user message."""
    if not candidates:
        return (
            "Binary inventory: (empty — no analyzable binaries found in the ISO)\n"
            "Static-analysis tools will return an error until you `analyze_binary` "
            "something extracted manually via `extract_iso`."
        )
    lines = [
        "Binary inventory (all pre-analyzed; pick one with `switch_binary(<sha1>)`):",
        "",
        f"  {'label':<30} {'size':>12}  {'sha1':<42} {'fns':>6}  note",
    ]
    for c in candidates:
        note = f"  {c.note}" if c.note else ""
        lines.append(
            f"  {c.label:<30} {c.size:>12,}  {c.sha1:<42} {c.function_count:>6}{note}"
        )
    lines.extend(
        [
            "",
            "No default is selected. Call `switch_binary(<sha1>)` on the binary that "
            "most likely holds the game logic before using `entry_points`, "
            "`find_function`, etc. Bigger function count usually = more code.",
        ]
    )
    return "\n".join(lines)
