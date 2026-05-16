"""Agent prompts — shared blocks + task-specific system prompts."""

from src.agent.prompts.hud import HUD_SYSTEM_PROMPT, HUD_TASK_PREFIX
from src.agent.prompts.position import POSITION_SYSTEM_PROMPT
from src.agent.prompts.research import RESEARCH_SYSTEM_PROMPT

# Backwards compat — existing code imports these names
SYSTEM_PROMPT = HUD_SYSTEM_PROMPT
TASK_INPUT_PREFIX = HUD_TASK_PREFIX

__all__ = [
    "SYSTEM_PROMPT",
    "TASK_INPUT_PREFIX",
    "HUD_SYSTEM_PROMPT",
    "HUD_TASK_PREFIX",
    "POSITION_SYSTEM_PROMPT",
    "RESEARCH_SYSTEM_PROMPT",
]
