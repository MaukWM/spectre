"""Inspect AI `@task` entry point for spectre.

One task class today: `hud_off`. Single sample (Nightfire) baked in so
`inspect eval src/agent/task.py` runs without further config.

Web-UI mode (later) will dynamically build a Sample from uploaded files
and call into the same `Task` factory with that dataset.
"""

from __future__ import annotations

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Scorer, Target, accuracy, scorer
from inspect_ai.solver import TaskState, basic_agent, system_message

from src.agent.discovery import format_inventory, survey_and_analyze
from src.agent.discovery_tools import (
    analyze_binary,
    extract_iso,
    list_iso_contents,
    switch_binary,
)
from src.agent.ghidra_tools import (
    add_note,
    callees,
    callers,
    decompile,
    entry_points,
    find_function,
    find_string,
    rename_function,
)
from src.agent.loader import (
    build_sample,
    load_sample_config,
    resolve_optional_user_binary,
    resolve_runtime_paths,
)
from src.agent.prompts import SYSTEM_PROMPT
from src.agent.scorer import load_mask, score_against_mask
from src.agent.tools import _LAST_PASS_KEY, run_gecko
from src.dolphin import (
    collect_dump,
    load_png_frames,
    parse_gecko,
    read_game_id,
    run_dolphin,
)
from src.dolphin.diff import load_image_rgb
from src.dolphin.runner import write_user_dir

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"
SPECTRE_ROOT = Path(__file__).resolve().parents[2]
EXTRACT_ROOT = SPECTRE_ROOT / "cache" / "extracted"
DEFAULT_SAMPLE = "nightfire_hud_off"


def _extract_root_for(iso_path: Path) -> Path:
    """Scratch directory under `cache/extracted/` for files pulled from the ISO."""
    return EXTRACT_ROOT / iso_path.stem


@scorer(metrics=[accuracy()])
def hud_off_scorer(sample_dir: Path) -> Scorer:
    """Grade the agent's last submission.

    Re-runs Dolphin with the agent's final answer text parsed as Gecko,
    scores the resulting frame against the mask. No reliance on tool-call
    state — final scoring stands alone and re-verifies.
    """
    cfg = load_sample_config(sample_dir)

    async def score(state: TaskState, target: Target) -> Score:
        from inspect_ai.util import store

        gecko_text = state.output.completion or ""
        codes = parse_gecko(gecko_text)
        fallback_used = False
        if not codes:
            # Agent forgot to submit but a `run_gecko` call may have PASSed
            # earlier. Fall back to the last PASSing gecko text the tool
            # stashed in the Sample store.
            stashed = store().get(_LAST_PASS_KEY)
            if isinstance(stashed, str) and stashed.strip():
                gecko_text = stashed
                codes = parse_gecko(gecko_text)
                fallback_used = bool(codes)
        if not codes:
            return Score(
                value=INCORRECT,
                answer=gecko_text[:200],
                explanation="Final answer contained no parseable Gecko code.",
            )

        import shutil
        import tempfile

        iso, savestate = resolve_runtime_paths(cfg)
        tmp_root = Path(tempfile.mkdtemp(prefix="spectre_score_"))
        try:
            user_dir = tmp_root / "user"
            write_user_dir(user_dir, read_game_id(iso), codes)
            run_dolphin(
                user_dir=user_dir,
                iso=iso,
                log_path=tmp_root / "dolphin.log",
                savestate=savestate,
                run_seconds=cfg.run_seconds,
            )
            frames_dir = tmp_root / "frames"
            collect_dump(user_dir, frames_dir)
            frames = load_png_frames(frames_dir)
            if not frames:
                return Score(
                    value=INCORRECT,
                    answer=gecko_text[:200],
                    explanation="Final Dolphin run produced no frames.",
                )

            mask_score = score_against_mask(
                reference=load_image_rgb(sample_dir / "reference.png"),
                candidate=load_image_rgb(frames[max(frames)]),
                mask=load_mask(sample_dir / "mask.png"),
                hud_min_mean=cfg.score_hud_min_mean,
                preserve_max_mean=cfg.score_preserve_max_mean,
            )
            note = " (scorer fell back to last PASSing tool call)" if fallback_used else ""
            return Score(
                value=CORRECT if mask_score.passed else INCORRECT,
                answer=gecko_text[:200],
                explanation=(
                    f"hud_mean={mask_score.hud_mean:.2f} "
                    f"preserve_mean={mask_score.preserve_mean:.2f} "
                    f"{mask_score.verdict} — {mask_score.reason()}{note}"
                ),
            )
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    return score


@task
def hud_off(iso: str = "", savestate: str = "") -> Task:
    """Single-Sample HUD-removal task (Nightfire reference instance).

    Args:
        iso: Path to the game ISO. Overrides the SPECTRE_NIGHTFIRE_ISO env var.
        savestate: Path to the Dolphin savestate. Overrides SPECTRE_NIGHTFIRE_SAV.

    CLI usage::

        inspect eval src/agent/task.py -T iso=roms/nightfire.iso -T savestate=roms/GO7E69.s01
    """
    import os

    sample_dir = SAMPLES_DIR / DEFAULT_SAMPLE
    cfg = load_sample_config(sample_dir)

    # CLI -T overrides take precedence over env vars
    if iso:
        os.environ[cfg.iso_env] = iso
    if savestate:
        os.environ[cfg.savestate_env] = savestate

    iso_path, _ = resolve_runtime_paths(cfg)
    extract_root = _extract_root_for(iso_path)
    extract_root.mkdir(parents=True, exist_ok=True)

    # Include the user's env-supplied ELF (if any) so prior-run notes
    # under its SHA-1 cache survive into the inventory.
    extras: list[Path] = []
    user_binary = resolve_optional_user_binary(cfg)
    if user_binary is not None:
        extras.append(user_binary)

    # Pre-analyze every executable on the disc + extras. Cache-hit on
    # second run.
    inventory = survey_and_analyze(iso_path, extract_root, extras=extras)
    inventory_text = format_inventory(inventory)

    sample = build_sample(sample_dir, inventory_text=inventory_text)
    return Task(
        dataset=[sample],
        solver=basic_agent(
            init=system_message(SYSTEM_PROMPT),
            tools=[
                run_gecko(sample_dir),
                entry_points(),
                find_function(),
                find_string(),
                decompile(),
                callees(),
                callers(),
                rename_function(),
                add_note(),
                list_iso_contents(iso_path),
                extract_iso(iso_path, extract_root),
                analyze_binary(extract_root),
                switch_binary(),
            ],
            message_limit=200,
        ),
        scorer=hud_off_scorer(sample_dir),
    )
