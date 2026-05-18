"""Composable prompt builder — assembles a system prompt from a JobSpec."""

from __future__ import annotations

from src.agent.job_spec import Capability, EvaluationMethod, GoalType, JobSpec
from src.agent.prompts.shared import (
    SUBMISSION_DOCUMENT,
    TOOLS_ANNOTATION,
    TOOLS_BINARY_DISCOVERY,
    TOOLS_FINDINGS,
    TOOLS_PPC_ASM,
    TOOLS_RESEARCH,
    TOOLS_RUNTIME,
    TOOLS_SAVESTATE_FINDINGS,
    TOOLS_STATIC_ANALYSIS,
    WORKFLOW_TOP_DOWN,
)
from src.agent.prompts.strategies.find_code_patch import (
    GECKO_FORMAT,
    PATCHING_PATTERNS,
    ROBUSTNESS,
    STRATEGY_INTERACTIVE,
    STRATEGY_VISUAL,
)
from src.agent.prompts.strategies.find_ram_address import (
    STRATEGY as RAM_STRATEGY,
)
from src.agent.prompts.strategies.static_research import (
    STRATEGY as RESEARCH_STRATEGY,
)


def build_system_prompt(spec: JobSpec, *, controller_mapping: str = "") -> str:
    """Assemble a system prompt from a JobSpec and optional context."""
    sections: list[str] = []

    # 1. Role + Goal
    sections.append(_role_block(spec))

    # 2. Tool documentation (only for enabled capabilities)
    sections.append("## Tooling")

    if Capability.STATIC_RE in spec.capabilities:
        sections.append(TOOLS_STATIC_ANALYSIS)
        sections.append(TOOLS_ANNOTATION)

    if Capability.DISCOVERY in spec.capabilities:
        sections.append(TOOLS_BINARY_DISCOVERY)

    if Capability.GECKO_INJECTION in spec.capabilities:
        if spec.uses_visual_gecko:
            sections.append(_tools_visual_gecko(spec))
        else:
            sections.append(_tools_interactive_gecko())
        sections.append(TOOLS_PPC_ASM)

    if Capability.RAM_POKE in spec.capabilities or Capability.INPUT_INJECTION in spec.capabilities:
        sections.append(TOOLS_RUNTIME)

    if Capability.INPUT_INJECTION in spec.capabilities and controller_mapping:
        sections.append(f"## Controller mapping\n\n{controller_mapping}")

    # 3. Knowledge base tools (always available)
    sections.append(TOOLS_FINDINGS)
    sections.append(TOOLS_RESEARCH)

    # Savestate findings (if runtime capable)
    if spec.needs_savestate:
        sections.append(TOOLS_SAVESTATE_FINDINGS)

    # 4. Workflow guidance
    if Capability.STATIC_RE in spec.capabilities:
        sections.append(WORKFLOW_TOP_DOWN)

    # 5. Goal-specific strategy
    sections.append(_goal_strategy(spec))

    # 6. Input-mutation hints
    if spec.input_mutation_hints:
        sections.append(_hints_block(spec))

    # 7. Submission guidance
    sections.append(SUBMISSION_DOCUMENT)

    return "\n\n".join(s for s in sections if s)


def _role_block(spec: JobSpec) -> str:
    """Opening role + goal description."""
    base = "You are an expert reverse engineer"

    if spec.goal_type == GoalType.FIND_CODE_PATCH:
        role = (
            f"{base} who finds Gecko cheat codes for GameCube games "
            f"emulated on Dolphin."
        )
        if spec.target_description:
            role += f"\n\nYour specific job: {spec.target_description}"
    elif spec.goal_type == GoalType.FIND_RAM_ADDRESS:
        role = (
            f"{base} analyzing a GameCube game running live on Dolphin. "
            f"Your job is to find specific RAM addresses and verify them "
            f"against the game's code."
        )
        if spec.target_description:
            role += f"\n\nYour specific job: {spec.target_description}"
    else:
        role = (
            f"{base} analyzing a GameCube game binary running on Dolphin. "
            f"Your job is to explore the codebase, understand game systems, "
            f"and document your findings thoroughly."
        )
        if spec.target_description:
            role += f"\n\nResearch focus: {spec.target_description}"

    return role


def _tools_visual_gecko(spec: JobSpec) -> str:
    """Tool docs for the HUD-style run_gecko verification loop."""
    return (
        "### Verification (budget-capped)\n\n"
        "- `run_gecko(gecko_text)` — applies your candidate Gecko code, runs "
        "headless Dolphin against the pinned ISO + savestate, captures a frame, "
        "returns per-region pixel-diff stats vs the reference baseline + the "
        f"captured frame itself as an image. **Budget-capped** ({spec.max_gecko_runs} calls). "
        "Use only on candidates you have a real argument for."
    )


def _tools_interactive_gecko() -> str:
    """Tool docs for the interactive apply+inspect Gecko workflow."""
    return (
        "### Gecko code tools\n\n"
        "- `apply_gecko_code(gecko_text)` — reboot Dolphin from the same savestate "
        "with your Gecko code applied. Returns a screenshot of the new state. "
        "Format: one or more `$Name` blocks followed by hex-pair lines. "
        "After rebooting, all runtime tools (memory, input, position) work on "
        "the new session.\n"
        "- `save_gecko_code(gecko_text)` — persist your final working Gecko code. "
        "Call this ONLY after you've confirmed the code works.\n"
        "- `capture_screenshot()` — grab the current Dolphin frame as an image. "
        "Useful for visual inspection during testing."
    )


def _goal_strategy(spec: JobSpec) -> str:
    """Goal-specific strategy and workflow guidance."""
    if spec.goal_type == GoalType.FIND_CODE_PATCH:
        parts = [GECKO_FORMAT, PATCHING_PATTERNS, ROBUSTNESS]
        if spec.uses_visual_gecko:
            parts.append(STRATEGY_VISUAL)
        else:
            parts.append(STRATEGY_INTERACTIVE)
        return "\n\n".join(parts)
    elif spec.goal_type == GoalType.FIND_RAM_ADDRESS:
        return RAM_STRATEGY
    else:
        return RESEARCH_STRATEGY


def _hints_block(spec: JobSpec) -> str:
    """Format input-mutation hints for the agent."""
    lines = ["## Input-mutation hints", ""]
    lines.append(
        "The following hints describe how specific inputs should affect "
        "the target values. Use these to verify your candidates:"
    )
    lines.append("")
    for hint in spec.input_mutation_hints:
        lines.append(f"- **{hint.input_description}** → {hint.expected_effect}")
    return "\n".join(lines)
