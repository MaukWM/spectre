"""Data model: Project (one game/ISO) and Task (one agent run within a project)."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from src.logging import logger

PROJECTS_ROOT = Path("/app/sessions") if Path("/app/sessions").exists() else Path("./sessions")
ISO_CACHE_ROOT = Path("/app/cache/isos") if Path("/app/cache").exists() else Path("./cache/isos")


# ── Task state machine ─────────────────────────────────────────────────── #


class TaskState(StrEnum):
    CREATED = "created"
    SAVESTATE_UPLOADED = "savestate_uploaded"
    FRAME_READY = "frame_ready"
    MASK_READY = "mask_ready"
    READY = "ready"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


_TASK_TRANSITIONS: dict[TaskState, set[TaskState]] = {
    TaskState.CREATED: {TaskState.SAVESTATE_UPLOADED, TaskState.FRAME_READY, TaskState.READY},
    TaskState.SAVESTATE_UPLOADED: {TaskState.FRAME_READY, TaskState.READY},
    TaskState.FRAME_READY: {TaskState.FRAME_READY, TaskState.MASK_READY, TaskState.READY},
    TaskState.MASK_READY: {TaskState.FRAME_READY, TaskState.READY},
    TaskState.READY: {TaskState.RUNNING},
    TaskState.RUNNING: {TaskState.DONE, TaskState.FAILED},
    TaskState.DONE: {TaskState.READY},
    TaskState.FAILED: {TaskState.READY},
}


# ── Config dataclasses ─────────────────────────────────────────────────── #


@dataclass
class ProjectConfig:
    """Persisted project metadata (one per game/ISO)."""

    project_id: str
    created_at: float = field(default_factory=time.time)

    # User-editable display name (defaults to game_id).
    name: str = ""

    # Set after ISO upload.
    game_id: str = ""
    iso_sha1: str = ""
    iso_size: int = 0

    # Ghidra survey progress.
    survey_binaries_total: int = 0
    survey_binaries_done: int = 0
    survey_complete: bool = False
    inventory_text: str = ""
    # Map of label → {sha1, function_count} for analyzed binaries.
    analyzed_binaries: dict[str, dict[str, object]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.analyzed_binaries is None:
            self.analyzed_binaries = {}


@dataclass
class SavestateConfig:
    """Persisted savestate metadata (project-level, shared across tasks)."""

    savestate_id: str
    name: str = ""
    notes: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class TaskConfig:
    """Persisted task metadata (one agent run within a project)."""

    task_id: str
    state: TaskState = TaskState.CREATED
    created_at: float = field(default_factory=time.time)

    # The job spec (serialized dict). This is the single source of truth
    # for what the task does. Replaces the old task_type + scattered fields.
    job_spec: dict[str, Any] = field(default_factory=dict)

    # Reference to a project-level savestate.
    savestate_id: str = ""

    # Result (set after run).
    result_verdict: str = ""
    result_gecko: str = ""
    result_hud_mean: float = 0.0
    result_preserve_mean: float = 0.0

    # ── Legacy fields (for migration only) ──────────────────────── #
    # These are read during deserialization for backwards compat
    # but new tasks should use job_spec exclusively.
    task_type: str = ""
    run_seconds: int = 10
    verify_budget: int = 8
    hud_min_mean: float = 5.0
    preserve_max_mean: float = 6.0
    hint: str = ""
    prompt_fields: dict[str, str] = field(default_factory=dict)

    def get_job_spec(self) -> Any:
        """Return a JobSpec instance, migrating legacy configs if needed."""
        from src.agent.job_spec import JobSpec

        if self.job_spec:
            return JobSpec.from_dict(self.job_spec)

        # Legacy migration: convert old task_type to a JobSpec
        return _migrate_legacy_config(self)

    @property
    def preset_name(self) -> str:
        """Return the preset name if this was created from a preset."""
        return self.job_spec.get("_preset", "") if self.job_spec else self.task_type


# ── Task ────────────────────────────────────────────────────────────────── #


class Task:
    """Manages one task's directory and state within a project."""

    def __init__(self, root: Path, config: TaskConfig) -> None:
        self.root = root
        self.config = config

    @property
    def task_id(self) -> str:
        return self.config.task_id

    @property
    def state(self) -> TaskState:
        return self.config.state

    @property
    def reference_path(self) -> Path:
        return self.root / "reference.png"

    @property
    def mask_path(self) -> Path:
        return self.root / "mask.png"

    @property
    def config_path(self) -> Path:
        return self.root / "config.json"

    @property
    def events_path(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def result_gecko_path(self) -> Path:
        return self.root / "result.gecko"

    @property
    def result_frame_path(self) -> Path:
        return self.root / "result_frame.png"

    def transition(self, new_state: TaskState) -> None:
        allowed = _TASK_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            raise ValueError(f"cannot transition {self.state} -> {new_state}")
        logger.info("task_transition", task=self.task_id, old=self.state, new=new_state)
        self.config.state = new_state
        self.save()

    def save(self) -> None:
        self.config_path.write_text(json.dumps(asdict(self.config), indent=2))

    def append_event(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", time.time())
        with self.events_path.open("a") as f:
            f.write(json.dumps(event) + "\n")

    def status_dict(self) -> dict[str, Any]:
        d = asdict(self.config)
        d["has_savestate"] = bool(self.config.savestate_id)
        d["has_reference"] = self.reference_path.exists()
        d["has_mask"] = self.mask_path.exists()
        return d


# ── Savestate ──────────────────────────────────────────────────────────── #


class Savestate:
    """Manages one project-level savestate directory."""

    def __init__(self, root: Path, config: SavestateConfig) -> None:
        self.root = root
        self.config = config

    @property
    def savestate_id(self) -> str:
        return self.config.savestate_id

    @property
    def savestate_path(self) -> Path:
        return self.root / "savestate.sav"

    @property
    def screenshot_path(self) -> Path:
        return self.root / "screenshot.png"

    @property
    def config_path(self) -> Path:
        return self.root / "config.json"

    def save(self) -> None:
        self.config_path.write_text(json.dumps(asdict(self.config), indent=2))

    def status_dict(self) -> dict[str, Any]:
        d = asdict(self.config)
        d["has_file"] = self.savestate_path.exists()
        d["has_screenshot"] = self.screenshot_path.exists()
        return d


# ── Project ─────────────────────────────────────────────────────────────── #


class Project:
    """Manages one project (game/ISO) and its tasks."""

    def __init__(self, root: Path, config: ProjectConfig) -> None:
        self.root = root
        self.config = config

    @property
    def project_id(self) -> str:
        return self.config.project_id

    @property
    def game_id(self) -> str:
        return self.config.game_id

    @property
    def iso_path(self) -> Path:
        return self.root / "iso.iso"

    @property
    def config_path(self) -> Path:
        return self.root / "config.json"

    @property
    def events_path(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def tasks_dir(self) -> Path:
        return self.root / "tasks"

    def save(self) -> None:
        self.config_path.write_text(json.dumps(asdict(self.config), indent=2))

    def append_event(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", time.time())
        with self.events_path.open("a") as f:
            f.write(json.dumps(event) + "\n")

    def status_dict(self) -> dict[str, Any]:
        d = asdict(self.config)
        d["task_count"] = len(list(self.tasks_dir.iterdir())) if self.tasks_dir.exists() else 0
        return d

    @property
    def savestates_dir(self) -> Path:
        return self.root / "savestates"

    # ── Savestate management ─────────────────────────────────────────── #

    def create_savestate(self, name: str = "") -> Savestate:
        self.savestates_dir.mkdir(parents=True, exist_ok=True)
        sid = uuid.uuid4().hex[:8]
        ss_dir = self.savestates_dir / sid
        ss_dir.mkdir()
        config = SavestateConfig(savestate_id=sid, name=name)
        ss = Savestate(ss_dir, config)
        ss.save()
        logger.info("savestate_created", project=self.project_id, savestate=sid)
        return ss

    def get_savestate(self, savestate_id: str) -> Savestate | None:
        ss_dir = self.savestates_dir / savestate_id
        config_path = ss_dir / "config.json"
        if not config_path.exists():
            return None
        raw = json.loads(config_path.read_text())
        return Savestate(ss_dir, SavestateConfig(**raw))

    def list_savestates(self) -> list[SavestateConfig]:
        if not self.savestates_dir.exists():
            return []
        savestates = []
        for d in sorted(self.savestates_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            cfg = d / "config.json"
            if cfg.exists():
                raw = json.loads(cfg.read_text())
                savestates.append(SavestateConfig(**raw))
        return savestates

    # ── Task management ───────────────────────────────────────────────── #

    def create_task(
        self,
        task_type: str = "",
        *,
        job_spec_dict: dict[str, Any] | None = None,
        preset: str = "",
    ) -> Task:
        """Create a new task.

        Args:
            task_type: Legacy task type string (for backwards compat).
            job_spec_dict: A serialized JobSpec dict.
            preset: Name of a preset to load.
        """
        from src.agent.job_spec import JobSpec
        from src.agent.presets import get_preset

        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        tid = uuid.uuid4().hex[:8]
        task_dir = self.tasks_dir / tid
        task_dir.mkdir()

        # Resolve the job spec
        if job_spec_dict:
            spec = JobSpec.from_dict(job_spec_dict)
            spec_dict = spec.to_dict()
        elif preset:
            spec = get_preset(preset)
            spec_dict = spec.to_dict()
            spec_dict["_preset"] = preset
        elif task_type:
            # Legacy: map old task_type to preset
            legacy_map = {
                "hud_detection": "hud_removal",
                "research": "research",
                "position_discovery": "position_finding",
                "noclip": "noclip",
            }
            preset_name = legacy_map.get(task_type, "research")
            spec = get_preset(preset_name)
            spec_dict = spec.to_dict()
            spec_dict["_preset"] = preset_name
        else:
            spec = get_preset("hud_removal")
            spec_dict = spec.to_dict()
            spec_dict["_preset"] = "hud_removal"

        config = TaskConfig(task_id=tid, job_spec=spec_dict)
        task = Task(task_dir, config)
        task.save()
        label = preset or task_type or spec_dict.get("_preset", "custom")
        logger.info("task_created", project=self.project_id, task=tid, preset=label)
        return task

    def get_task(self, task_id: str) -> Task | None:
        task_dir = self.tasks_dir / task_id
        config_path = task_dir / "config.json"
        if not config_path.exists():
            return None
        raw = json.loads(config_path.read_text())
        return Task(task_dir, TaskConfig(**raw))

    def list_tasks(self) -> list[TaskConfig]:
        if not self.tasks_dir.exists():
            return []
        tasks = []
        for d in sorted(self.tasks_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            cfg = d / "config.json"
            if cfg.exists():
                raw = json.loads(cfg.read_text())
                tasks.append(TaskConfig(**raw))
        return tasks


# ── ProjectStore ────────────────────────────────────────────────────────── #


class ProjectStore:
    """Manages all projects on disk."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or PROJECTS_ROOT
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self) -> Project:
        pid = uuid.uuid4().hex[:12]
        project_dir = self.root / pid
        project_dir.mkdir(parents=True)
        config = ProjectConfig(project_id=pid)
        project = Project(project_dir, config)
        project.save()
        logger.info("project_created", project=pid)
        return project

    def get(self, project_id: str) -> Project | None:
        project_dir = self.root / project_id
        config_path = project_dir / "config.json"
        if not config_path.exists():
            return None
        raw = json.loads(config_path.read_text())
        return Project(project_dir, ProjectConfig(**raw))

    def list_projects(self) -> list[ProjectConfig]:
        projects = []
        for d in sorted(self.root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            cfg = d / "config.json"
            if cfg.exists():
                try:
                    raw = json.loads(cfg.read_text())
                    projects.append(ProjectConfig(**raw))
                except (json.JSONDecodeError, TypeError):
                    continue
        return projects


# ── Legacy migration ────────────────────────────────────────────────────── #


def _migrate_legacy_config(cfg: TaskConfig) -> Any:
    """Convert old task_type-based configs to a JobSpec."""
    from src.agent.presets import get_preset

    legacy_map = {
        "hud_detection": "hud_removal",
        "research": "research",
        "position_discovery": "position_finding",
        "noclip": "noclip",
    }
    preset_name = legacy_map.get(cfg.task_type, "research")
    spec = get_preset(preset_name)

    # Carry over any custom values from the legacy config
    if cfg.hint:
        spec.target_description = cfg.hint
    if cfg.verify_budget:
        spec.max_gecko_runs = cfg.verify_budget
    if cfg.run_seconds:
        spec.run_seconds = cfg.run_seconds
    if cfg.hud_min_mean != 5.0:
        spec.hud_min_mean = cfg.hud_min_mean
    if cfg.preserve_max_mean != 6.0:
        spec.preserve_max_mean = cfg.preserve_max_mean

    return spec
