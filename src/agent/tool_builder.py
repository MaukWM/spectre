"""Capability-gated tool assembly — builds tool lists from a JobSpec."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from inspect_ai.tool import Tool

from src.agent.job_spec import Capability, EvaluationMethod, JobSpec

if TYPE_CHECKING:
    from src.agent.runtime_tools import SessionRef
    from src.dolphin.session import DolphinSession


def build_tools(
    spec: JobSpec,
    *,
    project_root: Path,
    iso_path: Path,
    extract_root: Path,
    session: DolphinSession | SessionRef | None = None,
    savestate_root: Path | None = None,
    task_root: Path | None = None,
    task_id: str = "",
    # HUD-specific (only for pixel_diff_mask)
    task: Any | None = None,
    project: Any | None = None,
    savestate_path: Path | None = None,
) -> list[Tool]:
    """Assemble the tool list based on JobSpec capabilities."""
    tools: list[Tool] = []

    # Static RE tools (parameterless factories)
    if Capability.STATIC_RE in spec.capabilities:
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

        tools += [
            entry_points(),
            find_function(),
            find_string(),
            decompile(),
            callees(),
            callers(),
            rename_function(task_id=task_id),
            add_note(task_id=task_id),
        ]

    # Discovery tools
    if Capability.DISCOVERY in spec.capabilities:
        from src.agent.discovery_tools import (
            analyze_binary,
            extract_iso,
            list_iso_contents,
            switch_binary,
        )

        tools += [
            list_iso_contents(iso_path),
            extract_iso(iso_path, extract_root),
            analyze_binary(extract_root),
            switch_binary(),
        ]

    # Gecko injection — two flavors
    if Capability.GECKO_INJECTION in spec.capabilities:
        if spec.uses_visual_gecko:
            # HUD-style: run_gecko with mask scoring feedback
            assert task is not None and project is not None, "visual gecko requires task + project"
            from src.web.sample_builder import build_run_gecko_for_task

            tools.append(build_run_gecko_for_task(task, project, spec))
        else:
            # Interactive: apply_gecko_code + save output
            assert session is not None, "interactive gecko requires a session"
            assert savestate_path is not None, "interactive gecko requires savestate_path"
            assert task_root is not None, "interactive gecko requires task_root"
            from src.agent.runtime_tools import (
                apply_gecko_code,
                save_gecko_code,
            )

            _gdb_port = 6777 if Capability.RAM_POKE in spec.capabilities else None
            tools.append(apply_gecko_code(session, iso_path, savestate_path, gdb_port=_gdb_port))
            tools.append(save_gecko_code(task_root))

    # Frame capture
    if Capability.FRAME_CAPTURE in spec.capabilities and session is not None:
        from src.agent.runtime_tools import capture_screenshot

        tools.append(capture_screenshot(session))

    # RAM poke (live session required)
    if Capability.RAM_POKE in spec.capabilities:
        assert session is not None, "ram_poke requires a Dolphin session"
        from src.agent.runtime_tools import (
            find_writers,
            read_memory,
            read_memory_batch,
            scan_memory,
            scan_memory_diff,
        )

        tools += [
            read_memory(session),
            read_memory_batch(session),
            scan_memory(session),
            scan_memory_diff(session),
            find_writers(session),
        ]

    # Input injection
    if Capability.INPUT_INJECTION in spec.capabilities:
        assert session is not None, "input_injection requires a Dolphin session"
        from src.agent.runtime_tools import (
            press_button,
            sample_position,
            set_stick,
            wait,
        )

        tools += [
            press_button(session),
            set_stick(session),
            wait(session),
            sample_position(session),
        ]

    # PPC assembly helpers — always available alongside gecko injection
    if Capability.GECKO_INJECTION in spec.capabilities:
        from src.agent.ppc_tools import assemble_ppc, make_c2_hook

        tools += [assemble_ppc(), make_c2_hook()]

    # Knowledge base (always)
    from src.agent.findings_tools import list_findings, save_finding
    from src.agent.research_tools import list_research, read_research, write_research

    tools += [
        save_finding(project_root, task_id=task_id),
        list_findings(project_root),
        list_research(project_root),
        read_research(project_root),
        write_research(project_root, task_id=task_id),
    ]

    # Savestate findings (if savestate present)
    if savestate_root is not None:
        from src.agent.runtime_tools import (
            list_savestate_findings,
            save_savestate_finding,
        )

        tools += [
            save_savestate_finding(savestate_root, task_id=task_id),
            list_savestate_findings(savestate_root),
        ]

    # Wrap all tools with wind-down budget warning
    from src.agent.winddown import wrap_tools_with_winddown

    tools = wrap_tools_with_winddown(tools, spec.message_limit)

    return tools
