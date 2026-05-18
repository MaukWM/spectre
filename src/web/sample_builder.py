"""Build an Inspect AI Sample + Task from web project/task files.

Unified builder: reads a JobSpec from the task config and wires
prompts, tools, and scorers accordingly. No more per-task-type branches.
"""

from __future__ import annotations

import base64
import io
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from inspect_ai import Task as InspectTask
from inspect_ai.dataset import Sample
from inspect_ai.model import ChatMessageUser, ContentImage, ContentText
from inspect_ai.solver import basic_agent, system_message
from inspect_ai.tool import Tool, ToolResult, tool
from inspect_ai.util import store as inspect_store
from PIL import Image

from src.agent.job_spec import Capability, EvaluationMethod, JobSpec
from src.agent.prompts.builder import build_system_prompt
from src.agent.scorer import load_mask, score_against_mask
from src.agent.scorer_builder import build_scorer
from src.agent.state import BUDGET_KEY, LAST_PASS_KEY
from src.agent.tool_builder import build_tools
from src.dolphin import collect_dump, load_png_frames, parse_gecko, read_game_id, run_dolphin
from src.dolphin.diff import has_render_glitch, load_image_rgb
from src.dolphin.runner import RunResult, write_user_dir

# Max retries when a captured frame has a render glitch (black bar).
_MAX_GLITCH_RETRIES = 2
from src.findings import FindingsStore
from src.web.sessions import Project, Task


# ── Unified Sample builder ────────────────────────────────────────────── #


def build_sample(task: Task, project: Project, spec: JobSpec) -> Sample:
    """Construct an Inspect AI Sample from a project task + JobSpec."""
    pcfg = project.config
    inv_block = f"\n{pcfg.inventory_text}\n" if pcfg.inventory_text else ""

    # Inject prior findings (exclude function kind — visible via Ghidra renames)
    findings_store = FindingsStore.load(project.root)
    findings_block = ""
    non_func = [f for f in findings_store.findings if f.kind != "function"]
    if non_func:
        findings_block = (
            f"\n## Prior findings from earlier tasks\n\n"
            f"{findings_store.format_table(exclude_kinds={'function'})}\n"
        )

    # Inject research index
    research_dir = project.root / "research"
    research_block = ""
    if research_dir.exists():
        index_path = research_dir / "INDEX.md"
        if index_path.exists():
            index_text = index_path.read_text().strip()
            docs = sorted(p.name for p in research_dir.glob("*.md") if p.name != "INDEX.md")
            if docs or "No research yet" not in index_text:
                research_block = f"\n## Research journal from earlier tasks\n\n{index_text}\n"
                if docs:
                    research_block += (
                        "\nAvailable docs: "
                        + ", ".join(docs)
                        + "\nUse `read_research(filename)` to read any of these.\n"
                    )

    # Inject savestate findings (if savestate assigned)
    ss_findings_block = ""
    if task.config.savestate_id:
        ss = project.get_savestate(task.config.savestate_id)
        if ss is not None:
            ss_store = FindingsStore.load(ss.root)
            if ss_store.findings:
                ss_findings_block = (
                    f"\n## Savestate findings (runtime-specific)\n\n"
                    f"{ss_store.format_table()}\n"
                )

    # Inject controller mapping (for runtime tasks)
    ctrl_block = ""
    if Capability.INPUT_INJECTION in spec.capabilities:
        from src.web.controller_mapping import format_mapping_for_prompt, load_mapping

        ctrl_mapping = load_mapping(project.root)
        ctrl_block = f"\n## {format_mapping_for_prompt(ctrl_mapping)}\n"

    # Build the body
    body_parts = [f"Game: {pcfg.game_id}"]

    if spec.target_description:
        body_parts.append(f"Task: {spec.target_description}")

    if spec.uses_visual_gecko:
        body_parts.append(
            f"Budget: {spec.max_gecko_runs} test runs.\n"
            f"Scoring thresholds: HUD region mean diff >= {spec.hud_min_mean}, "
            f"preserve region mean diff <= {spec.preserve_max_mean}."
        )

    body_parts.append(inv_block)
    body_parts.append(findings_block)
    body_parts.append(research_block)
    body_parts.append(ss_findings_block)
    body_parts.append(ctrl_block)

    body = "\n".join(p for p in body_parts if p.strip())

    # Build content blocks
    content: list[ContentText | ContentImage] = [ContentText(text=body)]

    # Add reference frame + mask for visual tasks
    if spec.needs_mask and task.reference_path.exists() and task.mask_path.exists():
        content += [
            ContentText(text="Reference frame (current state):"),
            ContentImage(image=str(task.reference_path)),
            ContentText(text="Mask (white = target to remove, black = must preserve):"),
            ContentImage(image=str(task.mask_path)),
        ]

    return Sample(
        id=f"web_{project.project_id}_{task.task_id}",
        input=[ChatMessageUser(content=content)],
        target="",
        metadata={
            "project_id": project.project_id,
            "task_id": task.task_id,
            "game_id": pcfg.game_id,
        },
    )


# ── Unified Task builder ──────────────────────────────────────────────── #


def build_task_from_project_task(
    task: Task,
    project: Project,
    iso_path: Path,
    extract_root: Path,
) -> InspectTask:
    """Build a full Inspect AI Task from a web project task."""
    spec = task.config.get_job_spec()

    errors = spec.validate()
    if errors:
        raise ValueError(f"Invalid job spec: {'; '.join(errors)}")

    # Savestate enforcement
    if spec.needs_savestate and not task.config.savestate_id:
        raise ValueError("Job spec requires runtime capabilities but no savestate is assigned")

    # Build prompt
    controller_mapping = ""
    if Capability.INPUT_INJECTION in spec.capabilities:
        from src.web.controller_mapping import format_mapping_for_prompt, load_mapping

        controller_mapping = format_mapping_for_prompt(load_mapping(project.root))

    system_prompt = build_system_prompt(spec, controller_mapping=controller_mapping)

    # Build sample
    sample = build_sample(task, project, spec)

    # Session management
    session, session_ref, cleanup = _setup_session(spec, task, project, iso_path)

    # Resolve savestate root
    savestate_root = None
    savestate_path = None
    if task.config.savestate_id:
        ss = project.get_savestate(task.config.savestate_id)
        if ss is not None:
            savestate_root = ss.root
            savestate_path = ss.savestate_path

    # Build tools
    tools = build_tools(
        spec,
        project_root=project.root,
        iso_path=iso_path,
        extract_root=extract_root,
        session=session_ref or session,
        savestate_root=savestate_root,
        task_root=task.root,
        task_id=task.task_id,
        task=task,
        project=project,
        savestate_path=savestate_path,
    )

    # Build scorer — pass cleanup so the session stays alive for the eval
    scorer = build_scorer(
        spec,
        task=task,
        project=project,
        session_cleanup=cleanup,
    )

    # Build submit description based on goal type
    submit_desc = _submit_description(spec)

    return InspectTask(
        dataset=[sample],
        solver=basic_agent(
            init=system_message(system_prompt),
            tools=tools,
            message_limit=spec.message_limit,
            **({"submit_description": submit_desc} if submit_desc else {}),
        ),
        scorer=scorer,
    )


def _setup_session(
    spec: JobSpec,
    task: Task,
    project: Project,
    iso_path: Path,
) -> tuple[Any, Any, Any]:
    """Boot Dolphin session if needed. Returns (session, session_ref, cleanup_fn)."""
    if not spec.needs_dolphin_session:
        return None, None, lambda: None

    from src.agent.runtime_tools import SessionRef
    from src.dolphin.session import DolphinSession

    ss = project.get_savestate(task.config.savestate_id)
    if ss is None:
        raise ValueError(f"Savestate {task.config.savestate_id} not found")

    gdb_port = 6777 if Capability.RAM_POKE in spec.capabilities else None
    session_cm = DolphinSession.start(
        iso=iso_path,
        savestate=ss.savestate_path,
        pipe_input=Capability.INPUT_INJECTION in spec.capabilities,
        gdb_port=gdb_port,
    )
    raw_session = session_cm.__enter__()
    raw_session.wait_for_first_frame()

    # If interactive gecko is enabled, wrap in SessionRef for hot-swap
    if spec.uses_interactive_gecko:
        ref = SessionRef(raw_session)

        def _cleanup() -> None:
            try:
                current = ref.session
                # Clean up the gecko-swapped session's CM if it has one
                gecko_cm = getattr(current, "_gecko_cm", None)
                current.terminate()
                current.cleanup()
                if gecko_cm is not None:
                    gecko_cm.__exit__(None, None, None)
            except Exception:
                pass
            try:
                session_cm.__exit__(None, None, None)
            except Exception:
                pass

        return raw_session, ref, _cleanup
    else:

        def _cleanup() -> None:
            try:
                session_cm.__exit__(None, None, None)
            except Exception:
                pass

        return raw_session, None, _cleanup


def _submit_description(spec: JobSpec) -> str:
    """Build a submit description based on goal type."""
    from src.agent.job_spec import GoalType

    if spec.goal_type == GoalType.STATIC_RESEARCH:
        return (
            "Submit your research summary and end the task. "
            "Call this after you've saved findings and written "
            "research docs. Pass a concise summary of what you discovered."
        )
    elif spec.goal_type == GoalType.FIND_RAM_ADDRESS:
        return (
            "Submit your findings and end the task. "
            "Call this after you've saved the discovered addresses "
            "as savestate findings. Pass a summary of the addresses "
            "and how you verified them."
        )
    else:
        if spec.uses_interactive_gecko:
            return (
                "Submit your results and end the task. "
                "Call this after you've saved the working Gecko code via "
                "save_gecko_code(). Pass a summary of the code, what it "
                "patches, and how you verified it."
            )
        # Visual gecko: no special submit desc — agent submits gecko text as answer
        return ""


# ── Dolphin frame capture with glitch retry ────────────────────────────── #


@dataclass
class DolphinRunOutcome:
    """Result of a Dolphin run attempt, with crash diagnostics."""

    image: Any | None  # RGB numpy array or None
    crashed: bool = False
    returncode: int = 0
    elapsed: float = 0.0
    run_seconds_budget: int = 0

    @property
    def crash_detail(self) -> str:
        """Human-readable crash description for agent-facing messages."""
        if not self.crashed:
            return ""
        if self.returncode != 0 and self.elapsed < self.run_seconds_budget * 0.5:
            return (
                f"Dolphin crashed (exit code {self.returncode}) after "
                f"{self.elapsed:.1f}s — the game never rendered a frame. "
                f"Your Gecko code likely corrupted execution at the hook site."
            )
        return (
            f"Dolphin produced no frames in {self.elapsed:.1f}s "
            f"(budget {self.run_seconds_budget}s, exit code {self.returncode}). "
            f"The game may have crashed or entered an infinite loop before rendering."
        )


def _run_dolphin_with_retry(
    iso_path: Path,
    savestate_path: Path,
    codes: list,  # type: ignore[type-arg]
    run_seconds: int,
    max_retries: int = _MAX_GLITCH_RETRIES,
) -> DolphinRunOutcome:
    """Run Dolphin and capture frames, retrying if render glitch detected.

    Returns a ``DolphinRunOutcome`` with the candidate frame (or None) and
    crash diagnostics.
    """
    from src.logging import logger

    last_result: RunResult | None = None
    for attempt in range(1 + max_retries):
        tmp_root = Path(tempfile.mkdtemp(prefix="daywater_web_tool_"))
        try:
            user_dir = tmp_root / "user"
            game_id = read_game_id(iso_path)
            write_user_dir(user_dir, game_id, codes)
            last_result = run_dolphin(
                user_dir=user_dir,
                iso=iso_path,
                log_path=tmp_root / "dolphin.log",
                savestate=savestate_path,
                run_seconds=run_seconds,
            )

            # Ensure no orphan process lingers (belt + suspenders)
            _kill_orphan_dolphin(user_dir)

            frames_dir = tmp_root / "frames"
            collect_dump(user_dir, frames_dir)
            frames = load_png_frames(frames_dir)

            if not frames:
                logger.info(
                    "no_frames",
                    attempt=attempt + 1,
                    rc=last_result.returncode,
                    elapsed=round(last_result.elapsed_seconds, 1),
                    early_exit=last_result.elapsed_seconds < run_seconds * 0.8,
                )
                if attempt < max_retries:
                    continue
                return DolphinRunOutcome(
                    image=None,
                    crashed=True,
                    returncode=last_result.returncode,
                    elapsed=last_result.elapsed_seconds,
                    run_seconds_budget=run_seconds,
                )

            candidate_png = frames[max(frames)]
            candidate_img = load_image_rgb(candidate_png)

            if has_render_glitch(candidate_img) and attempt < max_retries:
                # Check if an earlier frame is clean
                clean_img = _find_clean_frame(frames)
                if clean_img is not None:
                    return DolphinRunOutcome(image=clean_img)
                logger.info("frame_retry_glitch", attempt=attempt + 1)
                continue

            return DolphinRunOutcome(image=candidate_img)
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    return DolphinRunOutcome(
        image=None,
        crashed=True,
        returncode=last_result.returncode if last_result else -1,
        elapsed=last_result.elapsed_seconds if last_result else 0.0,
        run_seconds_budget=run_seconds,
    )


def _kill_orphan_dolphin(user_dir: Path) -> None:
    """Kill any Dolphin process still referencing this user_dir."""
    import subprocess

    # Find PID of any dolphin-emu-nogui using this user_dir
    try:
        result = subprocess.run(
            ["pgrep", "-f", str(user_dir)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            pid = line.strip()
            if pid:
                subprocess.run(["kill", "-9", pid], check=False, timeout=5)
    except Exception:
        pass  # best-effort cleanup


def _find_clean_frame(frames: dict[int, Path]) -> Any | None:
    """Walk backwards through frames to find one without a render glitch."""
    for key in sorted(frames.keys(), reverse=True):
        img = load_image_rgb(frames[key])
        if not has_render_glitch(img):
            return img
    return None


# ── run_gecko tool for visual tasks ────────────────────────────────────── #


def build_run_gecko_for_task(task: Task, project: Project, spec: JobSpec) -> Tool:
    """Build the run_gecko tool for pixel-diff visual tasks."""

    @tool
    def run_gecko() -> Tool:
        async def execute(gecko_text: str) -> ToolResult:
            """Run Dolphin with a candidate Gecko code and score the result.

            Args:
                gecko_text: One or more `$Name` blocks followed by 16-char hex
                    pair lines.
            """
            used = int(inspect_store().get(BUDGET_KEY, 0))
            if used >= spec.max_gecko_runs:
                return f"Budget exhausted ({used}/{spec.max_gecko_runs}). Submit your best answer."
            inspect_store().set(BUDGET_KEY, used + 1)
            call_idx = used + 1
            remaining = spec.max_gecko_runs - call_idx

            codes = parse_gecko(gecko_text)
            if not codes:
                return f"Call {call_idx}/{spec.max_gecko_runs}: empty gecko text. ({remaining} remaining)"

            iso_path = project.iso_path.resolve()
            ss = project.get_savestate(task.config.savestate_id)
            if ss is None:
                return "Error: no savestate assigned to this task."
            savestate_path = ss.savestate_path

            outcome = _run_dolphin_with_retry(
                iso_path, savestate_path, codes, spec.run_seconds,
            )
            if outcome.image is None:
                return (
                    f"Call {call_idx}/{spec.max_gecko_runs}: {outcome.crash_detail} "
                    f"({remaining} remaining)"
                )

            mask_score = score_against_mask(
                reference=load_image_rgb(task.reference_path),
                candidate=outcome.image,
                mask=load_mask(task.mask_path),
                hud_min_mean=spec.hud_min_mean,
                preserve_max_mean=spec.preserve_max_mean,
            )

            if mask_score.passed:
                inspect_store().set(LAST_PASS_KEY, gecko_text)

            # Encode frame as data URL for multimodal feedback.
            img = Image.fromarray(outcome.image)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            data_url = f"data:image/png;base64,{b64}"

            verdict_text = (
                f"Call {call_idx}/{spec.max_gecko_runs} -- verdict: {mask_score.verdict}\n"
                f"  hud_mean      = {mask_score.hud_mean:.2f}  "
                f"(need >= {spec.hud_min_mean})\n"
                f"  preserve_mean = {mask_score.preserve_mean:.2f}  "
                f"(need <= {spec.preserve_max_mean})\n"
                f"  {mask_score.reason()}\n"
                f"  ({remaining} calls remaining)"
            )
            return [
                ContentText(text=verdict_text),
                ContentImage(image=data_url),
            ]

        return execute

    return run_gecko()
