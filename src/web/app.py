"""FastAPI application — serves the API and static frontend."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from src.findings import FindingsStore
from src.ghidra.notes import NotesStore
from src.web.events import stream_events
from src.web.mask import save_mask
from src.web.sessions import ProjectStore, TaskState
from src.web.uploads import save_iso, save_reference_frame, save_savestate

app = FastAPI(title="Spectre", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Project store — configurable root for dev vs Docker.
_projects_root = Path("/app/sessions") if Path("/app/sessions").exists() else Path("./sessions")
store = ProjectStore(_projects_root)


def _get_project(project_id: str):  # type: ignore[no-untyped-def]
    project = store.get(project_id)
    if project is None:
        raise HTTPException(404, f"Project {project_id} not found")
    return project


def _get_task(project_id: str, task_id: str):  # type: ignore[no-untyped-def]
    project = _get_project(project_id)
    task = project.get_task(task_id)
    if task is None:
        raise HTTPException(404, f"Task {task_id} not found in project {project_id}")
    return project, task


# ── Project CRUD ─────────────────────────────────────────────────────── #


@app.post("/api/projects")
async def create_project() -> dict[str, str]:
    project = store.create()
    return {"project_id": project.project_id}


@app.get("/api/projects")
async def list_projects() -> list[dict]:  # type: ignore[type-arg]
    return [
        {
            "project_id": p.project_id,
            "game_id": p.game_id,
            "iso_sha1": p.iso_sha1,
            "iso_size": p.iso_size,
            "survey_complete": p.survey_complete,
            "survey_binaries_done": p.survey_binaries_done,
            "created_at": p.created_at,
        }
        for p in store.list_projects()
    ]


@app.get("/api/projects/{project_id}")
async def get_project(project_id: str) -> dict:  # type: ignore[type-arg]
    project = _get_project(project_id)
    return project.status_dict()


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str) -> dict[str, bool]:
    project = _get_project(project_id)
    shutil.rmtree(project.root, ignore_errors=True)
    return {"ok": True}


# ── ISO Upload (project level) ──────────────────────────────────────── #


@app.post("/api/projects/{project_id}/upload/iso")
async def upload_iso(project_id: str, file: UploadFile, background_tasks: BackgroundTasks) -> dict:  # type: ignore[type-arg]
    project = _get_project(project_id)
    if project.config.game_id:
        raise HTTPException(400, "ISO already uploaded for this project")

    # Stream upload to temp file.
    tmp = Path(tempfile.mktemp(suffix=".iso", prefix="spectre_upload_"))
    size = 0
    with tmp.open("wb") as f:
        while chunk := await file.read(1 << 20):
            f.write(chunk)
            size += len(chunk)

    try:
        result = save_iso(project, tmp, size)
    except ValueError as e:
        tmp.unlink(missing_ok=True)
        raise HTTPException(400, str(e))

    # Kick off survey in background.
    from src.web.runner import run_survey

    async def _survey() -> None:
        p = _get_project(project_id)
        try:
            await run_survey(p)
        except Exception:
            pass  # logged inside run_survey

    background_tasks.add_task(_survey)

    return result


@app.get("/api/projects/{project_id}/events")
async def project_event_stream(project_id: str) -> StreamingResponse:
    project = _get_project(project_id)
    return StreamingResponse(
        stream_events(project),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Task CRUD ────────────────────────────────────────────────────────── #


@app.post("/api/projects/{project_id}/tasks")
async def create_task(project_id: str, body: dict | None = None) -> dict[str, str]:  # type: ignore[type-arg]
    project = _get_project(project_id)
    if not project.config.game_id:
        raise HTTPException(400, "Upload an ISO first")
    task_type = (body or {}).get("type", "hud_detection")
    task = project.create_task(task_type=task_type)
    return {"task_id": task.task_id, "task_type": task_type}


@app.get("/api/projects/{project_id}/tasks")
async def list_tasks(project_id: str) -> list[dict]:  # type: ignore[type-arg]
    project = _get_project(project_id)
    return [
        {
            "task_id": t.task_id,
            "task_type": t.task_type,
            "state": t.state,
            "result_verdict": t.result_verdict,
            "created_at": t.created_at,
        }
        for t in project.list_tasks()
    ]


@app.delete("/api/projects/{project_id}/tasks/{task_id}")
async def delete_task(project_id: str, task_id: str) -> dict[str, bool]:
    project, task = _get_task(project_id, task_id)
    shutil.rmtree(task.root, ignore_errors=True)
    return {"ok": True}


@app.get("/api/projects/{project_id}/tasks/{task_id}")
async def get_task_status(project_id: str, task_id: str) -> dict:  # type: ignore[type-arg]
    project, task = _get_task(project_id, task_id)
    d = task.status_dict()
    d["survey_complete"] = project.config.survey_complete
    d["survey_binaries_done"] = project.config.survey_binaries_done
    d["survey_binaries_total"] = project.config.survey_binaries_total
    return d


# ── Task file uploads ────────────────────────────────────────────────── #


@app.post("/api/projects/{project_id}/tasks/{task_id}/upload/savestate")
async def upload_savestate(project_id: str, task_id: str, file: UploadFile) -> dict:  # type: ignore[type-arg]
    project, task = _get_task(project_id, task_id)
    if task.state != TaskState.CREATED:
        raise HTTPException(400, f"Cannot upload savestate in state {task.state}")

    tmp = Path(tempfile.mktemp(suffix=".sav", prefix="spectre_upload_"))
    size = 0
    with tmp.open("wb") as f:
        while chunk := await file.read(1 << 20):
            f.write(chunk)
            size += len(chunk)

    try:
        result = save_savestate(task, tmp, size)
    except ValueError as e:
        tmp.unlink(missing_ok=True)
        raise HTTPException(400, str(e))
    return result


# ── Capture frame from Dolphin ───────────────────────────────────────── #


@app.post("/api/projects/{project_id}/tasks/{task_id}/capture")
async def capture_frame(project_id: str, task_id: str) -> dict:  # type: ignore[type-arg]
    project, task = _get_task(project_id, task_id)
    # Allow capture from multiple states (fixes re-capture bug).
    if task.state not in (TaskState.SAVESTATE_UPLOADED, TaskState.FRAME_READY, TaskState.MASK_READY):
        raise HTTPException(400, f"Cannot capture in state {task.state}")

    from src.web.runner import run_capture_frame

    frame_path = await run_capture_frame(task, project.iso_path)
    save_reference_frame(task, frame_path)
    return {"ok": True, "frame_url": f"/api/projects/{project_id}/tasks/{task_id}/files/reference.png"}


# ── Mask ─────────────────────────────────────────────────────────────── #


@app.post("/api/projects/{project_id}/tasks/{task_id}/mask")
async def submit_mask(project_id: str, task_id: str, file: UploadFile) -> dict:  # type: ignore[type-arg]
    project, task = _get_task(project_id, task_id)
    if task.state != TaskState.FRAME_READY:
        raise HTTPException(400, f"Cannot submit mask in state {task.state}")

    raw_bytes = await file.read()
    try:
        result = save_mask(task, raw_bytes)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Auto-transition to READY if survey is complete.
    if project.config.survey_complete:
        task.transition(TaskState.READY)

    return result


# ── Config update ────────────────────────────────────────────────────── #


@app.post("/api/projects/{project_id}/tasks/{task_id}/config")
async def update_config(project_id: str, task_id: str, body: dict) -> dict[str, bool]:  # type: ignore[type-arg]
    project, task = _get_task(project_id, task_id)
    for key in ("hint", "run_seconds", "verify_budget", "hud_min_mean", "preserve_max_mean"):
        if key in body:
            setattr(task.config, key, body[key])
    task.save()
    return {"ok": True}


# ── Agent run ────────────────────────────────────────────────────────── #


@app.post("/api/projects/{project_id}/tasks/{task_id}/run")
async def start_run(project_id: str, task_id: str, background_tasks: BackgroundTasks) -> dict[str, bool]:  # type: ignore[type-arg]
    project, task = _get_task(project_id, task_id)

    # Research tasks can go directly from CREATED to READY.
    if task.config.task_type == "research" and task.state == TaskState.CREATED:
        task.transition(TaskState.READY)

    if task.state != TaskState.READY:
        raise HTTPException(400, f"Cannot start run in state {task.state}")

    from src.web.runner import run_agent

    async def _run() -> None:
        p, t = _get_task(project_id, task_id)
        await run_agent(t, p)

    background_tasks.add_task(_run)
    return {"ok": True}


# ── SSE event stream (task level) ────────────────────────────────────── #


@app.get("/api/projects/{project_id}/tasks/{task_id}/events")
async def task_event_stream(project_id: str, task_id: str) -> StreamingResponse:
    project, task = _get_task(project_id, task_id)
    return StreamingResponse(
        stream_events(task),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Results ──────────────────────────────────────────────────────────── #


@app.get("/api/projects/{project_id}/tasks/{task_id}/result")
async def get_result(project_id: str, task_id: str) -> dict:  # type: ignore[type-arg]
    project, task = _get_task(project_id, task_id)
    if task.state not in (TaskState.DONE, TaskState.FAILED):
        raise HTTPException(400, f"No result yet (state: {task.state})")
    return {
        "verdict": task.config.result_verdict,
        "gecko": task.config.result_gecko,
        "hud_mean": task.config.result_hud_mean,
        "preserve_mean": task.config.result_preserve_mean,
        "has_frame": task.result_frame_path.exists(),
    }


@app.get("/api/projects/{project_id}/tasks/{task_id}/result.gecko")
async def download_gecko(project_id: str, task_id: str) -> FileResponse:
    project, task = _get_task(project_id, task_id)
    if not task.result_gecko_path.exists():
        raise HTTPException(404, "No gecko code found")
    game_id = project.config.game_id
    return FileResponse(
        task.result_gecko_path,
        media_type="text/plain",
        filename=f"{game_id}_hud_off.gecko",
    )


# ── Serve task files (reference, mask, result frame) ─────────────────── #


@app.get("/api/projects/{project_id}/tasks/{task_id}/files/{filename}")
async def get_task_file(project_id: str, task_id: str, filename: str) -> FileResponse:
    project, task = _get_task(project_id, task_id)
    allowed = {"reference.png", "mask.png", "result_frame.png", "config.json"}
    if filename not in allowed:
        raise HTTPException(403, f"File {filename} not serveable")
    path = task.root / filename
    if not path.exists():
        raise HTTPException(404, f"File {filename} not found")
    return FileResponse(path)


# ── Knowledge base (findings + Ghidra notes/renames) ─────────────────── #


@app.get("/api/projects/{project_id}/findings")
async def get_findings(project_id: str) -> list[dict]:  # type: ignore[type-arg]
    project = _get_project(project_id)
    fs = FindingsStore.load(project.root)
    from dataclasses import asdict

    return [asdict(f) for f in fs.list_all()]


@app.delete("/api/projects/{project_id}/findings/{finding_id}")
async def delete_finding(project_id: str, finding_id: str) -> dict[str, bool]:
    project = _get_project(project_id)
    fs = FindingsStore.load(project.root)
    if not fs.remove(finding_id):
        raise HTTPException(404, f"Finding {finding_id} not found")
    return {"ok": True}


@app.delete("/api/projects/{project_id}/knowledge")
async def reset_knowledge(project_id: str) -> dict[str, bool]:
    """Clear all findings, research docs, and Ghidra renames/notes."""
    project = _get_project(project_id)

    # Clear findings
    fs = FindingsStore.load(project.root)
    fs.findings.clear()
    fs._flush()

    # Clear research docs
    research_dir = project.root / "research"
    if research_dir.exists():
        shutil.rmtree(research_dir, ignore_errors=True)

    # Clear Ghidra notes/renames from all cached binaries
    cache_root = Path("cache/binaries")
    if not cache_root.exists():
        cache_root = Path("/app/cache/binaries")
    if cache_root.exists():
        for sha_dir in cache_root.iterdir():
            notes_path = sha_dir / "notes.json"
            if notes_path.exists():
                ns = NotesStore.load(sha_dir)
                if ns.renames or ns.notes:
                    ns.renames.clear()
                    ns.notes.clear()
                    ns._flush()

    return {"ok": True}


@app.get("/api/projects/{project_id}/research")
async def get_research_index(project_id: str) -> dict:  # type: ignore[type-arg]
    """Return the research index + list of available docs."""
    project = _get_project(project_id)
    research_dir = project.root / "research"
    if not research_dir.exists():
        return {"index": "", "docs": []}
    index_path = research_dir / "INDEX.md"
    index_text = index_path.read_text() if index_path.exists() else ""
    docs = sorted(p.name for p in research_dir.glob("*.md") if p.name != "INDEX.md")
    return {"index": index_text, "docs": docs}


@app.get("/api/projects/{project_id}/research/{filename}")
async def get_research_doc(project_id: str, filename: str) -> dict:  # type: ignore[type-arg]
    """Return a single research document."""
    project = _get_project(project_id)
    research_dir = project.root / "research"
    path = research_dir / filename
    if not path.exists() or not path.resolve().is_relative_to(research_dir.resolve()):
        raise HTTPException(404, f"Document {filename} not found")
    return {"filename": filename, "content": path.read_text()}


@app.get("/api/projects/{project_id}/knowledge")
async def get_knowledge(project_id: str) -> dict:  # type: ignore[type-arg]
    """Combined knowledge base: findings + all Ghidra renames/notes across cached binaries."""
    project = _get_project(project_id)

    # Findings
    fs = FindingsStore.load(project.root)
    from dataclasses import asdict

    findings = [asdict(f) for f in fs.list_all()]

    # Ghidra notes/renames from all analyzed binaries
    cache_root = Path("cache/binaries")
    if not cache_root.exists():
        cache_root = Path("/app/cache/binaries")

    renames: list[dict[str, str]] = []
    notes: list[dict[str, str]] = []

    if cache_root.exists():
        for sha_dir in sorted(cache_root.iterdir()):
            notes_path = sha_dir / "notes.json"
            if not notes_path.exists():
                continue
            ns = NotesStore.load(sha_dir)
            sha1 = sha_dir.name
            for addr, name in ns.renames.items():
                renames.append({"address": addr, "name": name, "binary": sha1[:8]})
            for addr, text in ns.notes.items():
                notes.append({"address": addr, "text": text, "binary": sha1[:8]})

    return {"findings": findings, "renames": renames, "notes": notes}


# ── Static frontend ─────────────────────────────────────────────────── #

_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")


# ── Entry point ──────────────────────────────────────────────────────── #


def main() -> None:
    import subprocess

    import uvicorn

    # Launch Inspect AI viewer on :7575 in background for fine-grained run inspection.
    inspect_proc = None
    try:
        inspect_proc = subprocess.Popen(
            ["inspect", "view", "--host", "0.0.0.0", "--port", "7575", "--log-dir", "/app/logs"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass  # inspect view is optional; web UI still works without it

    try:
        uvicorn.run(
            "src.web.app:app",
            host="0.0.0.0",
            port=7860,
            reload=False,
        )
    finally:
        if inspect_proc:
            inspect_proc.terminate()


if __name__ == "__main__":
    main()
