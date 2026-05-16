"""Sample loader: build an Inspect AI `Sample` from a sample directory.

A sample dir holds the static side of one task instance:

- `sample.toml`   — typed config (id, env vars, run/budget/thresholds)
- `hint.txt`      — natural-language brief shown to the agent
- `reference.png` — baseline frame (no cheat) shown to the agent
- `mask.png`      — B&W HUD mask shown to the agent and used by the scorer
- `expected.gecko`— ground-truth solution (sanity only; not shown)

The licensed ROM + savestate are resolved from env vars at load time so
nothing copyrighted enters the repo.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from inspect_ai.dataset import Sample
from inspect_ai.model import ChatMessageUser, ContentImage, ContentText

from src.agent.prompts import TASK_INPUT_PREFIX
from src.findings import FindingsStore

SPECTRE_ROOT = Path(__file__).resolve().parents[2]


def _resolve_path(raw: str) -> Path:
    """Expand `~`, anchor relative paths to the spectre repo root."""
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (SPECTRE_ROOT / p).resolve()
    else:
        p = p.resolve()
    return p


@dataclass(frozen=True)
class SampleConfig:
    """Typed view of `sample.toml`."""

    id: str
    game_id: str
    description: str
    iso_env: str
    savestate_env: str
    binary_env: str | None       # optional ELF/DOL override env var name
    run_seconds: int
    verify_budget: int
    score_hud_min_mean: float
    score_preserve_max_mean: float


def load_sample_config(sample_dir: Path) -> SampleConfig:
    raw = tomllib.loads((sample_dir / "sample.toml").read_text())
    return SampleConfig(
        id=raw["id"],
        game_id=raw["game_id"],
        description=raw.get("description", ""),
        iso_env=raw["iso_env"],
        savestate_env=raw["savestate_env"],
        binary_env=raw.get("binary_env"),
        run_seconds=int(raw["run_seconds"]),
        verify_budget=int(raw["verify_budget"]),
        score_hud_min_mean=float(raw["score_hud_min_mean"]),
        score_preserve_max_mean=float(raw["score_preserve_max_mean"]),
    )


def resolve_runtime_paths(cfg: SampleConfig) -> tuple[Path, Path]:
    """Resolve ISO + savestate paths from env vars. Raises if missing."""
    iso = os.environ.get(cfg.iso_env)
    sav = os.environ.get(cfg.savestate_env)
    if not iso or not sav:
        missing = [name for name, val in [(cfg.iso_env, iso), (cfg.savestate_env, sav)] if not val]
        raise RuntimeError(f"env vars not set: {missing}")
    iso_path = _resolve_path(iso)
    sav_path = _resolve_path(sav)
    if not iso_path.exists():
        raise FileNotFoundError(f"ISO not found at {iso_path} (from {cfg.iso_env})")
    if not sav_path.exists():
        raise FileNotFoundError(f"savestate not found at {sav_path} (from {cfg.savestate_env})")
    return iso_path, sav_path


def resolve_optional_user_binary(cfg: SampleConfig) -> Path | None:
    """Return the env-supplied ELF/DOL if `binary_env` is set + the file exists.

    Used to seed `survey_and_analyze`'s extras list so a user-supplied
    binary (typically a decomp project's full ELF, or a previously-
    analyzed copy with persisted notes) lands in the agent's inventory
    alongside the disc-extracted ones. Returns None if env unset, env
    empty, or path missing — caller decides whether to warn.
    """
    if not cfg.binary_env:
        return None
    raw = os.environ.get(cfg.binary_env)
    if not raw:
        return None
    p = _resolve_path(raw)
    return p if p.exists() else None


def resolve_binary_for_analysis(cfg: SampleConfig, sample_dir: Path) -> Path:
    """Return the binary Ghidra should analyze.

    Preference order:
    1. `binary_env` from sample.toml, if set and the path exists. Typically
       points at a full ELF reconstructed by a decomp project — covers RELs
       and the entire address space.
    2. `<sample_dir>/boot.dol` (extracted from the ISO by `extract_dol`).
       Lower fidelity: REL-loaded code is invisible.
    """
    if cfg.binary_env:
        raw = os.environ.get(cfg.binary_env)
        if raw:
            p = _resolve_path(raw)
            if p.exists():
                return p
    dol = (sample_dir / "boot.dol").resolve()
    if dol.exists():
        return dol
    raise FileNotFoundError(
        f"no analyzable binary: set {cfg.binary_env} to a real ELF, "
        f"or run `scripts/build_analysis.py` to extract {dol} from the ISO first"
    )


def build_sample(
    sample_dir: Path,
    *,
    inventory_text: str = "",
    project_root: Path | None = None,
) -> Sample:
    """Construct one Inspect AI `Sample` from a sample directory.

    `inventory_text`, when non-empty, is injected into the user message
    so the agent sees the full binary menu (every analyzed ELF / DOL /
    REL on the disc) and can pick one with `switch_binary` before
    using the static-analysis tools.

    `project_root`, when provided, loads prior findings and injects them
    into the user message.
    """
    cfg = load_sample_config(sample_dir)
    hint = (sample_dir / "hint.txt").read_text().strip()
    reference_png = sample_dir / "reference.png"
    mask_png = sample_dir / "mask.png"

    if not reference_png.exists() or not mask_png.exists():
        raise FileNotFoundError(
            f"reference.png or mask.png missing in {sample_dir}; "
            f"run scripts/gen_<sample>_assets.py first"
        )

    inv_block = f"\n{inventory_text}\n" if inventory_text else ""

    findings_block = ""
    research_block = ""
    if project_root is not None:
        findings_store = FindingsStore.load(project_root)
        non_func = [f for f in findings_store.findings if f.kind != "function"]
        if non_func:
            findings_block = (
                "\n## Prior findings from earlier tasks\n\n"
                f"{findings_store.format_table(exclude_kinds={'function'})}\n"
            )

        research_dir = project_root / "research"
        if research_dir.exists():
            index_path = research_dir / "INDEX.md"
            if index_path.exists():
                index_text = index_path.read_text().strip()
                docs = sorted(
                    p.name for p in research_dir.glob("*.md") if p.name != "INDEX.md"
                )
                if docs or "No research yet" not in index_text:
                    research_block = (
                        "\n## Research journal from earlier tasks\n\n"
                        f"{index_text}\n"
                    )
                    if docs:
                        research_block += (
                            "\nAvailable docs: " + ", ".join(docs)
                            + "\nUse `read_research(filename)` to read any of these.\n"
                        )

    body = (
        f"{TASK_INPUT_PREFIX}\n\n"
        f"Game: {cfg.description} (ID `{cfg.game_id}`).\n"
        f"Budget: {cfg.verify_budget} tool calls.\n"
        f"Scoring thresholds: HUD region mean diff ≥ {cfg.score_hud_min_mean}, "
        f"preserve region mean diff ≤ {cfg.score_preserve_max_mean}.\n"
        f"{inv_block}{findings_block}{research_block}\n"
        f"Hint:\n{hint}"
    )

    user_message = ChatMessageUser(
        content=[
            ContentText(text=body),
            ContentText(text="Reference frame (HUD currently present):"),
            ContentImage(image=str(reference_png)),
            ContentText(text="Mask (white = HUD to remove, black = must preserve):"),
            ContentImage(image=str(mask_png)),
        ],
    )

    return Sample(
        id=cfg.id,
        input=[user_message],
        target="",  # task is open-ended; scorer reads from sandbox state, not target
        metadata={
            "sample_dir": str(sample_dir),
            "config": cfg.__dict__,
        },
    )
