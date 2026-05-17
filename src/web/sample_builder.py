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
from src.agent.research_tools import list_research, read_research, write_research
from src.agent.scorer import load_mask, score_against_mask
from src.agent.tools import _LAST_PASS_KEY
from src.dolphin import collect_dump, load_png_frames, parse_gecko, read_game_id, run_dolphin
from src.dolphin.diff import load_image_rgb
from src.dolphin.input import InputSequence
from src.dolphin.runner import write_user_dir
from src.findings import FindingsStore
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
            f"\n## Prior findings from earlier tasks\n\n{findings_store.format_table(exclude_kinds={'function'})}\n"
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
                research_block = f"\n## Research journal from earlier tasks\n\n{index_text}\n"
                if docs:
                    research_block += (
                        "\nAvailable docs: "
                        + ", ".join(docs)
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


def _resolve_savestate_path(task: Task, project: Project) -> Path:
    """Resolve the savestate path from a task's savestate_id."""
    ss = project.get_savestate(task.config.savestate_id)
    if ss is None:
        raise ValueError(f"Savestate {task.config.savestate_id} not found in project")
    return ss.savestate_path


def _build_run_gecko_for_task(task: Task, project: Project):  # type: ignore[no-untyped-def]
    """Build the run_gecko tool bound to a project task's files."""
    import base64
    import io
    import shutil
    import tempfile

    from PIL import Image

    from src.agent.state import BUDGET_KEY, LAST_PASS_KEY

    tcfg = task.config
    savestate_path = _resolve_savestate_path(task, project)

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
                return f"Budget exhausted ({used}/{tcfg.verify_budget}). Submit your best answer."
            inspect_store().set(BUDGET_KEY, used + 1)
            call_idx = used + 1
            remaining = tcfg.verify_budget - call_idx

            codes = parse_gecko(gecko_text)
            if not codes:
                return f"Call {call_idx}/{tcfg.verify_budget}: empty gecko text. ({remaining} calls remaining)"

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
                    savestate=savestate_path,
                    run_seconds=tcfg.run_seconds,
                )
                frames_dir = tmp_root / "frames"
                collect_dump(user_dir, frames_dir)
                frames = load_png_frames(frames_dir)

                if not frames:
                    return f"Call {call_idx}/{tcfg.verify_budget}: no frames produced. ({remaining} calls remaining)"

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
    savestate_path = _resolve_savestate_path(task, project)

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
                savestate=savestate_path,
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
    if task.config.task_type == "position_discovery":
        return _build_position_discovery_task(task, project, iso_path, extract_root)
    if task.config.task_type == "noclip":
        return _build_noclip_task(task, project, iso_path, extract_root)

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
            f"\n## Prior findings from earlier tasks\n\n{findings_store.format_table(exclude_kinds={'function'})}\n"
        )

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

    body = f"Research task: {tcfg.hint}\n\nGame: {pcfg.game_id}\n{inv_block}{findings_block}{research_block}"

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


# ── Position discovery task ──────────────────────────────────────────── #


def _build_position_discovery_sample(task: Task, project: Project) -> Sample:
    """Build a Sample for a position discovery task."""
    pcfg = project.config
    tcfg = task.config
    inv_block = f"\n{pcfg.inventory_text}\n" if pcfg.inventory_text else ""

    # Inject prior knowledge
    findings_store = FindingsStore.load(project.root)
    findings_block = ""
    non_func = [f for f in findings_store.findings if f.kind != "function"]
    if non_func:
        findings_block = (
            f"\n## Prior findings from earlier tasks\n\n{findings_store.format_table(exclude_kinds={'function'})}\n"
        )

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

    # Inject savestate findings if any
    ss = project.get_savestate(tcfg.savestate_id)
    ss_findings_block = ""
    if ss is not None:
        ss_store = FindingsStore.load(ss.root)
        if ss_store.findings:
            ss_findings_block = f"\n## Existing savestate findings (runtime-specific)\n\n{ss_store.format_table()}\n"

    # Inject controller mapping
    from src.web.controller_mapping import format_mapping_for_prompt, load_mapping

    ctrl_mapping = load_mapping(project.root)
    ctrl_block = f"\n## {format_mapping_for_prompt(ctrl_mapping)}\n"

    body = (
        f"Position discovery task: {tcfg.hint}\n\n"
        f"Game: {pcfg.game_id}\n"
        f"{inv_block}{findings_block}{research_block}{ss_findings_block}{ctrl_block}"
    )

    return Sample(
        id=f"position_{project.project_id}_{task.task_id}",
        input=[ChatMessageUser(content=[ContentText(text=body)])],
        target="",
        metadata={
            "project_id": project.project_id,
            "task_id": task.task_id,
            "game_id": pcfg.game_id,
        },
    )


@scorer(metrics=[accuracy()])
def position_discovery_scorer(savestate_root: Path, session_cleanup) -> Scorer:  # type: ignore[no-untyped-def]
    """Score position discovery: check findings have addresses + code verification."""

    async def score(state: InspectTaskState, target: Target) -> Score:
        try:
            fs = FindingsStore.load(savestate_root)
            addr_findings = [f for f in fs.findings if f.kind == "address"]
            labels = {f.label.lower() for f in addr_findings}
            has_position = any(
                axis in label
                for label in labels
                for axis in ("player_x", "player_y", "player_z", "pos_x", "pos_y", "pos_z")
            )

            # Check that findings include code verification (PC/function references)
            code_verified = sum(
                1 for f in addr_findings if any(kw in f.detail.lower() for kw in ("pc=", "pc =", "written by", "0x80"))
            )

            answer = state.output.completion or ""
            if len(addr_findings) >= 3 and has_position:
                note = ""
                if code_verified < 3:
                    note = f" Warning: only {code_verified}/3 findings include code verification."
                return Score(
                    value=CORRECT,
                    answer=answer[:200],
                    explanation=(
                        f"Found {len(addr_findings)} address findings. "
                        f"Labels: {', '.join(f.label for f in addr_findings)}.{note}"
                    ),
                )
            return Score(
                value=INCORRECT,
                answer=answer[:200],
                explanation=(
                    f"Need at least 3 address findings with position labels. "
                    f"Got {len(addr_findings)} findings: "
                    f"{', '.join(f.label for f in addr_findings) or 'none'}"
                ),
            )
        finally:
            # Clean up the DolphinSession
            session_cleanup()

    return score


def _build_position_discovery_task(
    task: Task,
    project: Project,
    iso_path: Path,
    extract_root: Path,
) -> InspectTask:
    """Build an Inspect AI Task for runtime position discovery."""
    from src.agent.prompts import POSITION_SYSTEM_PROMPT
    from src.agent.runtime_tools import (
        find_writers,
        list_savestate_findings,
        press_button,
        read_memory,
        read_memory_batch,
        sample_position,
        save_savestate_finding,
        scan_memory,
        scan_memory_diff,
        set_stick,
        wait,
    )
    from src.dolphin.session import DolphinSession

    ss = project.get_savestate(task.config.savestate_id)
    if ss is None:
        raise ValueError(f"Savestate {task.config.savestate_id} not found")

    sample = _build_position_discovery_sample(task, project)

    # Boot DolphinSession — stays alive for entire agent run.
    # We enter the context manager manually and clean up in the scorer.
    session_cm = DolphinSession.start(
        iso=iso_path,
        savestate=ss.savestate_path,
        pipe_input=True,
        gdb_port=6777,
    )
    session = session_cm.__enter__()
    session.wait_for_first_frame()

    def _cleanup() -> None:
        try:
            session_cm.__exit__(None, None, None)
        except Exception:
            pass

    return InspectTask(
        dataset=[sample],
        solver=basic_agent(
            init=system_message(POSITION_SYSTEM_PROMPT),
            tools=[
                # Runtime tools
                read_memory(session),
                read_memory_batch(session),
                scan_memory(session),
                scan_memory_diff(session),
                find_writers(session),
                press_button(session),
                set_stick(session),
                wait(session),
                sample_position(session),
                # Savestate findings
                save_savestate_finding(ss.root),
                list_savestate_findings(ss.root),
                # Static analysis tools
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
                "Submit your position discovery results and end the task. "
                "Call this after you've saved player_x, player_y, and player_z "
                "as savestate findings. Pass a summary of the addresses and "
                "how you verified them."
            ),
            message_limit=200,
        ),
        scorer=position_discovery_scorer(ss.root, _cleanup),
    )


# ── Noclip task ──────────────────────────────────────────────────────── #


def _build_noclip_sample(task: Task, project: Project) -> Sample:
    """Build a Sample for a noclip / freecam task."""
    pcfg = project.config
    tcfg = task.config
    inv_block = f"\n{pcfg.inventory_text}\n" if pcfg.inventory_text else ""

    # Project-level findings
    findings_store = FindingsStore.load(project.root)
    findings_block = ""
    non_func = [f for f in findings_store.findings if f.kind != "function"]
    if non_func:
        findings_block = (
            f"\n## Prior findings from earlier tasks\n\n{findings_store.format_table(exclude_kinds={'function'})}\n"
        )

    # Research docs
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

    # Savestate findings (position addresses, etc.)
    ss = project.get_savestate(tcfg.savestate_id)
    ss_findings_block = ""
    if ss is not None:
        ss_store = FindingsStore.load(ss.root)
        if ss_store.findings:
            ss_findings_block = f"\n## Savestate findings (runtime-specific)\n\n{ss_store.format_table()}\n"

    # Controller mapping
    from src.web.controller_mapping import format_mapping_for_prompt, load_mapping

    ctrl_mapping = load_mapping(project.root)
    ctrl_block = f"\n## {format_mapping_for_prompt(ctrl_mapping)}\n"

    pf = tcfg.prompt_fields
    if pf:
        objective = pf.get("objective", tcfg.hint)
        controls = pf.get("expected_controls", "")
        task_block = f"## Objective\n\n{objective}\n"
        if controls:
            task_block += f"\n## Expected noclip controls\n\n{controls}\n"
    else:
        task_block = f"Noclip / freecam task: {tcfg.hint}\n"

    body = (
        f"{task_block}\n"
        f"Game: {pcfg.game_id}\n"
        f"{inv_block}{findings_block}{research_block}{ss_findings_block}{ctrl_block}"
    )

    return Sample(
        id=f"noclip_{project.project_id}_{task.task_id}",
        input=[ChatMessageUser(content=[ContentText(text=body)])],
        target="",
        metadata={
            "project_id": project.project_id,
            "task_id": task.task_id,
            "game_id": pcfg.game_id,
        },
    )


@scorer(metrics=[accuracy()])
def noclip_scorer(  # type: ignore[no-untyped-def]
    task_root: Path,
    savestate_root: Path,
    iso_path: Path,
    savestate_path: Path,
    session_cleanup,
) -> Scorer:
    """Deterministic noclip scorer.

    Boots Dolphin fresh from the savestate with the agent's Gecko code, walks
    forward for several seconds, and checks whether all three position axes
    changed. If the savestate was prepared so the player looks at an angle,
    forward movement changes X, Y, and Z — proving free flight.
    """

    async def score(state: InspectTaskState, target: Target) -> Score:
        import time as _time

        from src.dolphin.session import DolphinSession

        # Always clean up the agent's session first
        session_cleanup()

        code_path = task_root / "noclip_code.txt"
        if not code_path.exists():
            return Score(
                value=INCORRECT,
                answer=(state.output.completion or "")[:200],
                explanation="No noclip code saved — agent must call save_noclip_code().",
            )

        gecko_text = code_path.read_text()
        codes = parse_gecko(gecko_text)
        if not codes:
            return Score(
                value=INCORRECT,
                answer=(state.output.completion or "")[:200],
                explanation="Saved gecko code is empty or unparseable.",
            )

        # Load position addresses from savestate findings
        fs = FindingsStore.load(savestate_root)
        addr_findings = {f.label.lower(): f.address for f in fs.findings if f.kind == "address"}

        pos_addrs: dict[str, int] = {}
        for axis in ("player_x", "player_y", "player_z"):
            raw = addr_findings.get(axis) or addr_findings.get(axis.replace("player_", "pos_"))
            if raw:
                try:
                    pos_addrs[axis] = int(raw, 16)
                except ValueError:
                    pass

        if len(pos_addrs) < 3:
            return Score(
                value=INCORRECT,
                answer=(state.output.completion or "")[:200],
                explanation=(f"Need player_x/y/z address findings in savestate. Found: {list(pos_addrs.keys())}"),
            )

        x_addr = pos_addrs["player_x"]
        y_addr = pos_addrs["player_y"]
        z_addr = pos_addrs["player_z"]

        # Boot fresh Dolphin with the gecko code
        try:
            with DolphinSession.start(
                iso=iso_path,
                savestate=savestate_path,
                gecko_codes=codes,
                pipe_input=True,
            ) as session:
                if not session.wait_for_first_frame():
                    return Score(
                        value=INCORRECT,
                        answer=(state.output.completion or "")[:200],
                        explanation="Dolphin failed to produce frames with gecko code.",
                    )

                # Let game settle
                _time.sleep(3.0)

                # Look up with C-stick to ensure vertical movement is
                # possible (noclip fly modes follow camera direction).
                session.play_sequence(InputSequence.look_up(1.5))
                _time.sleep(0.5)

                # Walk forward for 5 seconds while sampling position.
                # If noclip works, all 3 axes change (including Y from
                # the upward camera angle).
                session.play_sequence_async(InputSequence.walk_forward(5.0))

                # Sample position during movement
                samples = session.sample_position_over_time(x_addr, y_addr, z_addr, duration=5.0, interval=0.5)

                if len(samples) < 3:
                    return Score(
                        value=INCORRECT,
                        answer=(state.output.completion or "")[:200],
                        explanation="Too few position samples collected during verification.",
                    )

                # Check displacement
                dx = abs(samples[-1].x - samples[0].x)
                dy = abs(samples[-1].y - samples[0].y)
                dz = abs(samples[-1].z - samples[0].z)
                total = (dx**2 + dy**2 + dz**2) ** 0.5

                # Thresholds: position should change meaningfully in at least 2 axes
                min_axis_delta = 0.5  # minimum change per axis to count as "moved"
                axes_moved = sum(1 for d in (dx, dy, dz) if d > min_axis_delta)

                summary = f"dX={dx:.2f} dY={dy:.2f} dZ={dz:.2f} total={total:.2f} axes_moved={axes_moved}/3"

                if axes_moved >= 2 and total > 5.0:
                    return Score(
                        value=CORRECT,
                        answer=(state.output.completion or "")[:200],
                        explanation=f"Noclip verified: {summary}. Player moved freely.",
                    )

                return Score(
                    value=INCORRECT,
                    answer=(state.output.completion or "")[:200],
                    explanation=(
                        f"Insufficient movement: {summary}. Need >=2 axes with delta >0.5 and total displacement >5.0."
                    ),
                )
        except Exception as e:
            return Score(
                value=INCORRECT,
                answer=(state.output.completion or "")[:200],
                explanation=f"Scorer error: {e}",
            )

    return score


def _build_noclip_task(
    task: Task,
    project: Project,
    iso_path: Path,
    extract_root: Path,
) -> InspectTask:
    """Build an Inspect AI Task for noclip / freecam Gecko code generation."""
    from src.agent.prompts import NOCLIP_SYSTEM_PROMPT
    from src.agent.runtime_tools import (
        SessionRef,
        apply_gecko_code,
        capture_screenshot,
        find_writers,
        list_savestate_findings,
        press_button,
        read_memory,
        read_memory_batch,
        sample_position,
        save_noclip_code,
        save_savestate_finding,
        scan_memory,
        scan_memory_diff,
        set_stick,
        wait,
    )
    from src.dolphin.session import DolphinSession

    ss = project.get_savestate(task.config.savestate_id)
    if ss is None:
        raise ValueError(f"Savestate {task.config.savestate_id} not found")

    sample = _build_noclip_sample(task, project)

    # Boot DolphinSession — stays alive for the agent run.
    # Wrapped in SessionRef so apply_gecko_code can swap it.
    session_cm = DolphinSession.start(
        iso=iso_path,
        savestate=ss.savestate_path,
        pipe_input=True,
    )
    raw_session = session_cm.__enter__()
    raw_session.wait_for_first_frame()

    session_ref = SessionRef(raw_session)

    def _cleanup() -> None:
        """Terminate whatever session is currently active."""
        try:
            current = session_ref.session
            # If the session was swapped by apply_gecko_code, the original
            # context manager is already exited. Terminate the current one.
            current.terminate()
            current.cleanup()
        except Exception:
            pass
        try:
            session_cm.__exit__(None, None, None)
        except Exception:
            pass

    return InspectTask(
        dataset=[sample],
        solver=basic_agent(
            init=system_message(NOCLIP_SYSTEM_PROMPT),
            tools=[
                # Noclip-specific tools
                apply_gecko_code(session_ref, iso_path, ss.savestate_path),
                save_noclip_code(task.root),
                capture_screenshot(session_ref),
                # Runtime tools (bound to SessionRef — auto-follows reboots)
                read_memory(session_ref),  # type: ignore[arg-type]
                read_memory_batch(session_ref),  # type: ignore[arg-type]
                scan_memory(session_ref),  # type: ignore[arg-type]
                scan_memory_diff(session_ref),  # type: ignore[arg-type]
                find_writers(session_ref),  # type: ignore[arg-type]
                press_button(session_ref),  # type: ignore[arg-type]
                set_stick(session_ref),  # type: ignore[arg-type]
                wait(session_ref),  # type: ignore[arg-type]
                sample_position(session_ref),  # type: ignore[arg-type]
                # Savestate findings
                save_savestate_finding(ss.root),
                list_savestate_findings(ss.root),
                # Static analysis tools
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
                "Submit your noclip results and end the task. "
                "Call this after you've saved the working Gecko code via "
                "save_noclip_code(). Pass a summary of the code, what it "
                "patches, and how you verified it."
            ),
            message_limit=200,
        ),
        scorer=noclip_scorer(task.root, ss.root, iso_path, ss.savestate_path, _cleanup),
    )
