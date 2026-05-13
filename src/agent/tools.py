"""Inspect AI tool: `run_gecko` — test a candidate Gecko code.

Closure-captured per-Sample so each solve gets a private budget counter.
Returns multimodal content: a one-line verdict + the result frame as an
inline image, so a multimodal LLM can both reason over numbers and see
what actually rendered.
"""

from __future__ import annotations

import base64
import shutil
import tempfile
from pathlib import Path

from inspect_ai.model import ContentImage, ContentText
from inspect_ai.tool import Tool, ToolResult, tool
from inspect_ai.util import store

from src.agent.loader import load_sample_config, resolve_runtime_paths
from src.agent.scorer import load_mask, score_against_mask
from src.agent.state import BUDGET_KEY as _BUDGET_KEY
from src.agent.state import LAST_PASS_KEY as _LAST_PASS_KEY
from src.dolphin import (
    collect_dump,
    load_png_frames,
    parse_gecko,
    read_game_id,
    run_dolphin,
)
from src.dolphin.diff import load_image_rgb
from src.dolphin.runner import write_user_dir
from src.logging import logger


def _png_to_data_url(p: Path) -> str:
    b64 = base64.b64encode(p.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{b64}"


@tool
def run_gecko(sample_dir: Path) -> Tool:
    """Build the `run_gecko` tool bound to a specific sample.

    Args:
        sample_dir: Path to the sample directory (provides config + assets).
    """
    cfg = load_sample_config(sample_dir)
    reference_png = sample_dir / "reference.png"
    mask_png = sample_dir / "mask.png"

    async def execute(gecko_text: str) -> ToolResult:
        """Run Dolphin with a candidate Gecko code and score the result.

        Args:
            gecko_text: One or more `$Name` blocks followed by 16-char hex
                pair lines, exactly as you'd paste into Dolphin's per-game
                INI. Comments and blank lines are allowed.

        Returns:
            A short verdict line plus the resulting frame as an image. If
            the budget is exhausted, returns a message saying so and does
            not run Dolphin.
        """
        used = int(store().get(_BUDGET_KEY, 0))
        if used >= cfg.verify_budget:
            return (
                f"Budget exhausted ({used}/{cfg.verify_budget}). "
                f"Submit your best answer; the final scorer will rerun whatever you last tried."
            )
        store().set(_BUDGET_KEY, used + 1)
        call_idx = used + 1
        remaining = cfg.verify_budget - call_idx

        try:
            iso, savestate = resolve_runtime_paths(cfg)
        except (RuntimeError, FileNotFoundError) as exc:
            return f"Setup error: {exc}"

        codes = parse_gecko(gecko_text)
        if not codes:
            return (
                f"Call {call_idx}/{cfg.verify_budget}: empty gecko text. "
                f"Need at least one `$Name` block plus one or more hex-pair lines. "
                f"({remaining} calls remaining)"
            )

        tmp_root = Path(tempfile.mkdtemp(prefix="spectre_tool_"))
        try:
            user_dir = tmp_root / "user"
            write_user_dir(user_dir, read_game_id(iso), codes)
            result = run_dolphin(
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
                return (
                    f"Call {call_idx}/{cfg.verify_budget}: Dolphin produced "
                    f"no PNG frames (rc={result.returncode}). Possible: the "
                    f"code crashed the emulator. ({remaining} calls remaining)"
                )

            candidate_png = frames[max(frames)]
            score = score_against_mask(
                reference=load_image_rgb(reference_png),
                candidate=load_image_rgb(candidate_png),
                mask=load_mask(mask_png),
                hud_min_mean=cfg.score_hud_min_mean,
                preserve_max_mean=cfg.score_preserve_max_mean,
            )

            logger.info(
                "tool_call_done",
                call=call_idx,
                hud_mean=round(score.hud_mean, 2),
                preserve_mean=round(score.preserve_mean, 2),
                verdict=score.verdict,
            )

            # Remember the most recent PASS so the final scorer can fall back
            # to it if the agent forgets to submit a textual answer.
            if score.passed:
                store().set(_LAST_PASS_KEY, gecko_text)

            verdict_text = (
                f"Call {call_idx}/{cfg.verify_budget} — verdict: {score.verdict}\n"
                f"  hud_mean      = {score.hud_mean:.2f}  "
                f"(need ≥ {cfg.score_hud_min_mean}, larger = HUD covered)\n"
                f"  preserve_mean = {score.preserve_mean:.2f}  "
                f"(need ≤ {cfg.score_preserve_max_mean}, smaller = scene preserved)\n"
                f"  {score.reason()}\n"
                f"  ({remaining} calls remaining)"
            )
            return [
                ContentText(text=verdict_text),
                ContentImage(image=_png_to_data_url(candidate_png)),
            ]
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    return execute
