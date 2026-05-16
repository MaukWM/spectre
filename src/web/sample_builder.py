"""Build an Inspect AI Sample + Task from web project/task files.

Bridges the web layer to the existing agent pipeline. Produces the same
data structures as `src.agent.loader.build_sample` but from uploaded
files instead of a sample.toml directory.
"""

from __future__ import annotations

from pathlib import Path

from inspect_ai import Task as InspectTask
from inspect_ai.dataset import Sample
from inspect_ai.model import ChatMessageUser, ContentImage, ContentText
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Scorer, Target, accuracy, scorer
from inspect_ai.solver import TaskState as InspectTaskState
from inspect_ai.solver import basic_agent, system_message
from inspect_ai.tool import Tool, ToolResult, tool
from inspect_ai.util import store as inspect_store

from src.agent.discovery_tools import (
    analyze_binary,
    extract_iso,
    list_iso_contents,
    switch_binary,
)
from src.agent.findings_tools import list_findings, save_finding
from src.agent.research_tools import list_research, read_research, write_research
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
from src.agent.prompts import RESEARCH_SYSTEM_PROMPT, SYSTEM_PROMPT, TASK_INPUT_PREFIX
from src.agent.scorer import load_mask, score_against_mask
from src.agent.tools import _LAST_PASS_KEY
from src.findings import FindingsStore
from src.dolphin import collect_dump, load_png_frames, parse_gecko, read_game_id, run_dolphin
from src.dolphin.diff import load_image_rgb
from src.dolphin.runner import write_user_dir
from src.web.sessions import Project, Task


def build_sample_from_task(task: Task, project: Project) -> Sample:
    """Construct an Inspect AI Sample from a project's task files."""
    pcfg = project.config
    tcfg = task.config
    inv_block = f"\n{pcfg.inventory_text}\n" if pcfg.inventory_text else ""

    # Inject prior findings (exclude function kind — already visible via Ghidra renames)
    findings_store = FindingsStore.load(project.root)
    findings_block = ""
    non_func = [f for f in findings_store.findings if f.kind != "function"]
    if non_func:
        findings_block = (
            "\n## Prior findings from earlier tasks\n\n"
            f"{findings_store.format_table(exclude_kinds={'function'})}\n"
        )

    # Inject research index if any docs exist
    research_dir = project.root / "research"
    research_block = ""
    if research_dir.exists():
        index_path = research_dir / "INDEX.md"
        if index_path.exists():
            index_text = index_path.read_text().strip()
            docs = sorted(p.name for p in research_dir.glob("*.md") if p.name != "INDEX.md")
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
        f"Game: {pcfg.game_id}\n"
        f"Budget: {tcfg.verify_budget} tool calls.\n"
        f"Scoring thresholds: HUD region mean diff >= {tcfg.hud_min_mean}, "
        f"preserve region mean diff <= {tcfg.preserve_max_mean}.\n"
        f"{inv_block}{findings_block}{research_block}\n"
        f"Hint:\n{tcfg.hint}"
    )

    user_message = ChatMessageUser(
        content=[
            ContentText(text=body),
            ContentText(text="Reference frame (HUD currently present):"),
            ContentImage(image=str(task.reference_path)),
            ContentText(text="Mask (white = HUD to remove, black = must preserve):"),
            ContentImage(image=str(task.mask_path)),
        ],
    )

    return Sample(
        id=f"web_{project.project_id}_{task.task_id}",
        input=[user_message],
        target="",
        metadata={
            "project_id": project.project_id,
            "task_id": task.task_id,
            "game_id": pcfg.game_id,
        },
    )


def _build_run_gecko_for_task(task: Task, project: Project):  # type: ignore[no-untyped-def]
    """Build the run_gecko tool bound to a project task's files."""
    import base64
    import io
    import shutil
    import tempfile

    from PIL import Image

    from src.agent.state import BUDGET_KEY, LAST_PASS_KEY

    tcfg = task.config

    @tool
    def run_gecko() -> Tool:
        async def execute(gecko_text: str) -> ToolResult:
            """Run Dolphin with a candidate Gecko code and score the result.

            Args:
                gecko_text: One or more `$Name` blocks followed by 16-char hex
                    pair lines.
            """
            used = int(inspect_store().get(BUDGET_KEY, 0))
            if used >= tcfg.verify_budget:
                return (
                    f"Budget exhausted ({used}/{tcfg.verify_budget}). "
                    f"Submit your best answer."
                )
            inspect_store().set(BUDGET_KEY, used + 1)
            call_idx = used + 1
            remaining = tcfg.verify_budget - call_idx

            codes = parse_gecko(gecko_text)
            if not codes:
                return (
                    f"Call {call_idx}/{tcfg.verify_budget}: empty gecko text. "
                    f"({remaining} calls remaining)"
                )

            iso_path = project.iso_path.resolve()
            tmp_root = Path(tempfile.mkdtemp(prefix="spectre_web_tool_"))
            try:
                user_dir = tmp_root / "user"
                game_id = read_game_id(iso_path)
                write_user_dir(user_dir, game_id, codes)
                run_dolphin(
                    user_dir=user_dir,
                    iso=iso_path,
                    log_path=tmp_root / "dolphin.log",
                    savestate=task.savestate_path,
                    run_seconds=tcfg.run_seconds,
                )
                frames_dir = tmp_root / "frames"
                collect_dump(user_dir, frames_dir)
                frames = load_png_frames(frames_dir)

                if not frames:
                    return (
                        f"Call {call_idx}/{tcfg.verify_budget}: no frames produced. "
                        f"({remaining} calls remaining)"
                    )

                candidate_png = frames[max(frames)]
                score = score_against_mask(
                    reference=load_image_rgb(task.reference_path),
                    candidate=load_image_rgb(candidate_png),
                    mask=load_mask(task.mask_path),
                    hud_min_mean=tcfg.hud_min_mean,
                    preserve_max_mean=tcfg.preserve_max_mean,
                )

                if score.passed:
                    inspect_store().set(LAST_PASS_KEY, gecko_text)

                # Encode frame as data URL for multimodal feedback.
                img = Image.open(candidate_png)
                img.load()
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                b64 = base64.b64encode(buf.getvalue()).decode("ascii")
                data_url = f"data:image/png;base64,{b64}"

                verdict_text = (
                    f"Call {call_idx}/{tcfg.verify_budget} -- verdict: {score.verdict}\n"
                    f"  hud_mean      = {score.hud_mean:.2f}  "
                    f"(need >= {tcfg.hud_min_mean})\n"
                    f"  preserve_mean = {score.preserve_mean:.2f}  "
                    f"(need <= {tcfg.preserve_max_mean})\n"
                    f"  {score.reason()}\n"
                    f"  ({remaining} calls remaining)"
                )
                return [
                    ContentText(text=verdict_text),
                    ContentImage(image=data_url),
                ]
            finally:
                shutil.rmtree(tmp_root, ignore_errors=True)

        return execute

    return run_gecko()


@scorer(metrics=[accuracy()])
def web_scorer(task: Task, project: Project) -> Scorer:
    """Grade the agent's final submission for a web task."""
    tcfg = task.config

    async def score(state: InspectTaskState, target: Target) -> Score:
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

        import shutil
        import tempfile

        iso_path = project.iso_path.resolve()
        tmp_root = Path(tempfile.mkdtemp(prefix="spectre_web_score_"))
        try:
            user_dir = tmp_root / "user"
            game_id = read_game_id(iso_path)
            write_user_dir(user_dir, game_id, codes)
            run_dolphin(
                user_dir=user_dir,
                iso=iso_path,
                log_path=tmp_root / "dolphin.log",
                savestate=task.savestate_path,
                run_seconds=tcfg.run_seconds,
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

            last_frame = frames[max(frames)]

            # Copy result frame to task dir for the web UI.
            import shutil as _sh

            _sh.copy2(str(last_frame), str(task.result_frame_path))

            mask_score = score_against_mask(
                reference=load_image_rgb(task.reference_path),
                candidate=load_image_rgb(last_frame),
                mask=load_mask(task.mask_path),
                hud_min_mean=tcfg.hud_min_mean,
                preserve_max_mean=tcfg.preserve_max_mean,
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
            shutil.rmtree(tmp_root, ignore_errors=True)

    return score


def build_task_from_project_task(
    task: Task,
    project: Project,
    iso_path: Path,
    extract_root: Path,
) -> InspectTask:
    """Build a full Inspect AI Task from a web project task."""
    if task.config.task_type == "research":
        return _build_research_task(task, project, iso_path, extract_root)

    sample = build_sample_from_task(task, project)

    return InspectTask(
        dataset=[sample],
        solver=basic_agent(
            init=system_message(SYSTEM_PROMPT),
            tools=[
                _build_run_gecko_for_task(task, project),
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
                save_finding(project.root),
                list_findings(project.root),
                list_research(project.root),
                read_research(project.root),
                write_research(project.root),
            ],
            message_limit=200,
        ),
        scorer=web_scorer(task, project),
    )


# ── Research task ─────────────────────────────────────────────────────── #


def _build_research_sample(task: Task, project: Project) -> Sample:
    """Build a Sample for a research (static-only) task."""
    pcfg = project.config
    tcfg = task.config
    inv_block = f"\n{pcfg.inventory_text}\n" if pcfg.inventory_text else ""

    # Inject prior knowledge (exclude function kind — visible via Ghidra renames)
    findings_store = FindingsStore.load(project.root)
    findings_block = ""
    non_func = [f for f in findings_store.findings if f.kind != "function"]
    if non_func:
        findings_block = (
            "\n## Prior findings from earlier tasks\n\n"
            f"{findings_store.format_table(exclude_kinds={'function'})}\n"
        )

    research_dir = project.root / "research"
    research_block = ""
    if research_dir.exists():
        index_path = research_dir / "INDEX.md"
        if index_path.exists():
            index_text = index_path.read_text().strip()
            docs = sorted(p.name for p in research_dir.glob("*.md") if p.name != "INDEX.md")
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
        f"Research task: {tcfg.hint}\n\n"
        f"Game: {pcfg.game_id}\n"
        f"{inv_block}{findings_block}{research_block}"
    )

    return Sample(
        id=f"research_{project.project_id}_{task.task_id}",
        input=[ChatMessageUser(content=[ContentText(text=body)])],
        target="",
        metadata={
            "project_id": project.project_id,
            "task_id": task.task_id,
            "game_id": pcfg.game_id,
        },
    )


@scorer(metrics=[accuracy()])
def research_scorer() -> Scorer:
    """Research tasks always pass — the value is in the findings/docs produced."""

    async def score(state: InspectTaskState, target: Target) -> Score:
        answer = state.output.completion or ""
        return Score(
            value=CORRECT,
            answer=answer[:200],
            explanation="Research task completed.",
        )

    return score


def _build_research_task(
    task: Task,
    project: Project,
    iso_path: Path,
    extract_root: Path,
) -> InspectTask:
    """Build an Inspect AI Task for static-only research."""
    sample = _build_research_sample(task, project)

    return InspectTask(
        dataset=[sample],
        solver=basic_agent(
            init=system_message(RESEARCH_SYSTEM_PROMPT),
            tools=[
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
                save_finding(project.root),
                list_findings(project.root),
                list_research(project.root),
                read_research(project.root),
                write_research(project.root),
            ],
            submit_description=(
                "Submit your research summary and end the task. "
                "Call this after you've saved findings and written "
                "research docs. Pass a concise summary of what you "
                "discovered as the answer."
            ),
            message_limit=200,
        ),
        scorer=research_scorer(),
    )
