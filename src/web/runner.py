"""Async wrappers for survey and agent eval."""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from src.logging import logger
from src.web.sessions import Project, Task, TaskState

_executor = ThreadPoolExecutor(max_workers=1)

_CACHE_ROOT = Path("/app/cache") if Path("/app/cache").exists() else Path("./cache")
_LOGS_ROOT = Path("/app/logs") if Path("/app/logs").exists() else Path("./logs")

# Global lock: only one heavy operation (survey or agent run) at a time.
_run_lock = asyncio.Lock()



async def run_survey(project: Project) -> None:
    """Run Ghidra survey in background, updating project state as it goes."""
    from src.agent.discovery import format_inventory, survey_and_analyze

    iso_path = project.iso_path.resolve()
    extract_root = _CACHE_ROOT / "extracted" / iso_path.stem

    project.append_event({"t": "survey_start"})

    async with _run_lock:
        try:
            loop = asyncio.get_event_loop()

            def _on_progress(done: int, total: int, label: str) -> None:
                project.config.survey_binaries_done = done
                project.config.survey_binaries_total = total
                project.save()
                project.append_event({
                    "t": "survey_progress",
                    "done": done,
                    "total": total,
                    "label": label,
                })

            def _run_survey() -> list:  # type: ignore[type-arg]
                return survey_and_analyze(
                    iso_path, extract_root, on_progress=_on_progress,
                )

            inventory = await loop.run_in_executor(_executor, _run_survey)

            project.config.inventory_text = format_inventory(inventory)
            project.config.analyzed_binaries = {
                c.label: {"sha1": c.sha1, "function_count": c.function_count}
                for c in inventory
            }
            project.config.survey_binaries_done = len(inventory)
            project.config.survey_binaries_total = len(inventory)
            project.config.survey_complete = True
            project.save()

            project.append_event({
                "t": "survey_done",
                "binaries": len(inventory),
                "inventory": [
                    {"label": c.label, "sha1": c.sha1, "functions": c.function_count, "size": c.size}
                    for c in inventory
                ],
            })
            logger.info("survey_done", project=project.project_id, binaries=len(inventory))

        except Exception as exc:
            project.append_event({"t": "survey_error", "error": str(exc)})
            logger.error("survey_failed", project=project.project_id, error=str(exc))
            raise


async def run_capture_frame(savestate_path: Path, iso_path: Path) -> Path:
    """Run Dolphin briefly from savestate to capture a reference frame."""
    from src.dolphin import collect_dump, load_png_frames, read_game_id, run_dolphin
    from src.dolphin.runner import write_user_dir

    iso_path = iso_path.resolve()

    async with _run_lock:
        loop = asyncio.get_event_loop()

        def _capture() -> Path:
            import os
            import subprocess
            import time as _time

            from src.dolphin.runner import _build_command, _terminate, check_savestate_compatibility

            tmp_root = Path(tempfile.mkdtemp(prefix="daywater_capture_"))
            user_dir = tmp_root / "user"
            game_id = read_game_id(iso_path)
            write_user_dir(user_dir, game_id, [])  # no gecko codes

            check_savestate_compatibility(savestate_path)
            args, uses_open_wrapper = _build_command(
                user_dir, iso_path, savestate=savestate_path,
                video_backend="Software", hidden=True,
            )
            env = os.environ.copy()
            env.setdefault("LC_ALL", "en_US.UTF-8")

            log_file = tmp_root / "dolphin.log"
            frames_dump_dir = user_dir / "Dump" / "Frames"

            with log_file.open("wb") as logf:
                proc = subprocess.Popen(args, stdout=logf, stderr=subprocess.STDOUT, env=env)
                try:
                    # Poll until we have at least 30 frames or 30s passes.
                    # Early frames from savestate load are often mid-render
                    # (half black), so we need to wait for the game to fully
                    # composite several frames before picking one.
                    deadline = _time.time() + 30
                    while _time.time() < deadline:
                        _time.sleep(0.5)
                        if proc.poll() is not None:
                            break  # Dolphin exited on its own
                        if frames_dump_dir.exists():
                            pngs = list(frames_dump_dir.glob("*.png"))
                            if len(pngs) >= 30:
                                break
                finally:
                    if proc.poll() is None:
                        _terminate(proc, uses_open_wrapper=uses_open_wrapper)

            frames_dir = tmp_root / "frames"
            collect_dump(user_dir, frames_dir)
            frames = load_png_frames(frames_dir)
            if not frames:
                log_tail = ""
                if log_file.exists():
                    log_tail = log_file.read_text()[-2000:]
                logger.error("capture_no_frames", dolphin_log=log_tail)
                shutil.rmtree(tmp_root, ignore_errors=True)
                raise RuntimeError("Dolphin produced no frames — check container logs for details")
            # Grab ~20th frame if available, otherwise last.
            # Early frames from savestate load are often half-rendered.
            sorted_keys = sorted(frames.keys())
            pick = sorted_keys[min(19, len(sorted_keys) - 1)]
            return frames[pick]

        frame_path = await loop.run_in_executor(_executor, _capture)
        return frame_path


async def run_agent(task: Task, project: Project) -> dict[str, Any]:
    """Run the full agent pipeline and return results."""
    from inspect_ai import eval as inspect_eval

    from src.web.sample_builder import build_task_from_project_task

    iso_path = project.iso_path.resolve()
    extract_root = _CACHE_ROOT / "extracted" / iso_path.stem

    task.transition(TaskState.RUNNING)
    task.append_event({"t": "agent_start"})

    async with _run_lock:
        loop = asyncio.get_event_loop()

        def _run() -> dict[str, Any]:
            inspect_task = build_task_from_project_task(task, project, iso_path, extract_root)

            # Model from env (INSPECT_EVAL_MODEL) or default to gpt-4o.
            import os

            model = os.environ.get("INSPECT_EVAL_MODEL", "openai/gpt-4o")
            results = inspect_eval(
                inspect_task,
                model=model,
                log_dir=str(_LOGS_ROOT),
            )

            if not results:
                return {"verdict": "FAILED", "error": "No eval results returned"}

            result = results[0]

            # Extract score info.
            if result.results and result.results.scores:
                score_data = result.results.scores[0]
                metrics = score_data.metrics
                accuracy_val = metrics.get("accuracy", {})
                acc = accuracy_val.value if hasattr(accuracy_val, "value") else 0.0
            else:
                acc = 0.0

            # Try to extract gecko text from the result.
            gecko_text = ""
            if result.samples:
                sample = result.samples[0]
                if sample.scores:
                    for score_key, score_val in sample.scores.items():
                        if hasattr(score_val, "answer") and score_val.answer:
                            gecko_text = score_val.answer
                            break

            return {
                "verdict": "PASS" if acc >= 1.0 else "FAIL",
                "gecko": gecko_text,
                "accuracy": acc,
                "log_file": str(result.location) if hasattr(result, "location") else "",
            }

        try:
            result = await loop.run_in_executor(_executor, _run)

            task.config.result_verdict = result.get("verdict", "FAIL")
            task.config.result_gecko = result.get("gecko", "")

            # Save gecko code to file for download.
            if result.get("gecko"):
                task.result_gecko_path.write_text(result["gecko"])

            if result["verdict"] == "PASS":
                task.transition(TaskState.DONE)
            else:
                task.transition(TaskState.FAILED)

            task.append_event({"t": "agent_done", **result})
            return result

        except Exception as exc:
            task.transition(TaskState.FAILED)
            task.append_event({"t": "agent_error", "error": str(exc)})
            logger.error("agent_failed", task=task.task_id, error=str(exc))
            return {"verdict": "FAILED", "error": str(exc)}
