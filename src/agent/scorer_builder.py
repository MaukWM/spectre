"""Evaluation method dispatch — builds scorers from a JobSpec."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from inspect_ai.scorer import CORRECT, Score, Scorer, Target, accuracy, scorer
from inspect_ai.solver import TaskState as InspectTaskState

from src.agent.job_spec import EvaluationMethod, JobSpec


def build_scorer(spec: JobSpec, **kwargs: Any) -> Scorer:
    """Build the appropriate scorer for a JobSpec's evaluation method.

    The ``session_cleanup`` kwarg MUST be passed for tasks that boot a
    DolphinSession. The scorer's closure captures it, which keeps the
    session context-manager alive for the entire eval run. Without this
    reference the generator is garbage-collected and Dolphin is killed.
    """
    session_cleanup: Callable[[], None] | None = kwargs.get("session_cleanup")

    if spec.evaluation == EvaluationMethod.PIXEL_DIFF_MASK:
        return _pixel_diff_scorer(
            task=kwargs["task"],
            project=kwargs["project"],
            spec=spec,
            session_cleanup=session_cleanup,
        )
    else:
        return _manual_review_scorer(session_cleanup=session_cleanup)


@scorer(metrics=[accuracy()])
def _pixel_diff_scorer(
    task: Any,
    project: Any,
    spec: JobSpec,
    session_cleanup: Callable[[], None] | None = None,
) -> Scorer:
    """Grade via pixel diff against mask — same logic as the old web_scorer."""
    from src.agent.scorer import load_mask, score_against_mask
    from src.agent.tools import _LAST_PASS_KEY
    from src.dolphin import parse_gecko
    from src.dolphin.diff import load_image_rgb

    savestate_path = _resolve_savestate_path(task, project)

    async def score(state: InspectTaskState, target: Target) -> Score:
        from inspect_ai.scorer import INCORRECT
        from inspect_ai.util import store as inspect_store

        try:
            gecko_text = state.output.completion or ""
            codes = parse_gecko(gecko_text)
            fallback_used = False
            if not codes:
                stashed = inspect_store().get(_LAST_PASS_KEY)
                if isinstance(stashed, str) and stashed.strip():
                    gecko_text = stashed
                    codes = parse_gecko(gecko_text)
                    fallback_used = bool(codes)
            if not codes:
                return Score(
                    value=INCORRECT,
                    answer=gecko_text[:200],
                    explanation="No parseable Gecko code in final answer.",
                )

            from src.web.sample_builder import _run_dolphin_with_retry

            iso_path = project.iso_path.resolve()
            outcome = _run_dolphin_with_retry(
                iso_path, savestate_path, codes, spec.run_seconds,
            )
            if outcome.image is None:
                return Score(
                    value=INCORRECT,
                    answer=gecko_text[:200],
                    explanation=f"Final Dolphin run produced no frames. {outcome.crash_detail}",
                )

            # Save result frame to task dir for the web UI.
            from PIL import Image as PILImage

            result_img = PILImage.fromarray(outcome.image)
            result_img.save(str(task.result_frame_path), "PNG")

            mask_score = score_against_mask(
                reference=load_image_rgb(task.reference_path),
                candidate=outcome.image,
                mask=load_mask(task.mask_path),
                hud_min_mean=spec.hud_min_mean,
                preserve_max_mean=spec.preserve_max_mean,
            )
            note = " (fallback)" if fallback_used else ""
            return Score(
                value=CORRECT if mask_score.passed else INCORRECT,
                answer=gecko_text[:200],
                explanation=(
                    f"hud_mean={mask_score.hud_mean:.2f} "
                    f"preserve_mean={mask_score.preserve_mean:.2f} "
                    f"{mask_score.verdict}{note}"
                ),
            )
        finally:
            if session_cleanup is not None:
                session_cleanup()

    return score


@scorer(metrics=[accuracy()])
def _manual_review_scorer(
    session_cleanup: Callable[[], None] | None = None,
) -> Scorer:
    """Always returns CORRECT — value is in findings/docs, not the score.

    Captures ``session_cleanup`` to keep the DolphinSession alive for the
    entire eval run (the closure prevents the context-manager generator
    from being garbage-collected).
    """

    async def score(state: InspectTaskState, target: Target) -> Score:
        try:
            answer = state.output.completion or ""
            return Score(
                value=CORRECT,
                answer=answer[:200],
                explanation="Task completed. Review findings and research docs for results.",
            )
        finally:
            if session_cleanup is not None:
                session_cleanup()

    return score


def _resolve_savestate_path(task: Any, project: Any) -> Path:
    """Resolve the savestate path from a task's savestate_id."""
    ss = project.get_savestate(task.config.savestate_id)
    if ss is None:
        raise ValueError(f"Savestate {task.config.savestate_id} not found in project")
    return ss.savestate_path
