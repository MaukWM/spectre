"""Async wrappers for survey and agent eval."""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import time as _time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from src.logging import logger
from src.web.sessions import Project, Task, TaskState

_executor = ThreadPoolExecutor(max_workers=1)

_CACHE_ROOT = Path("/app/cache") if Path("/app/cache").exists() else Path("./cache")
_LOGS_ROOT = Path("/app/logs") if Path("/app/logs").exists() else Path("./logs")
_SESSIONS_ROOT = Path("/app/sessions") if Path("/app/sessions").exists() else Path("./sessions")

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

            def _on_detail(msg: str) -> None:
                project.append_event({"t": "survey_detail", "msg": msg})

            def _run_survey() -> list:  # type: ignore[type-arg]
                return survey_and_analyze(
                    iso_path, extract_root,
                    on_progress=_on_progress,
                    on_detail=_on_detail,
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

            model = os.environ.get("INSPECT_EVAL_MODEL", "openai/gpt-5.5")
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


# ── Ghidra initialization ──────────────────────────────────────────────── #

_ghidra_init_events = _SESSIONS_ROOT / ".ghidra_init_events.jsonl"
_ghidra_init_running = False


def _emit_ghidra_event(event: dict[str, Any]) -> None:
    event.setdefault("ts", _time.time())
    with _ghidra_init_events.open("a") as f:
        f.write(json.dumps(event) + "\n")


async def run_ghidra_init() -> None:
    """Warm up Ghidra JVM + verify it can analyze a binary.

    Captures JVM stdout/stderr and emits progress events to a file
    that can be streamed via SSE.
    """
    global _ghidra_init_running  # noqa: PLW0603
    if _ghidra_init_running:
        return

    _ghidra_init_running = True
    _ghidra_init_events.parent.mkdir(parents=True, exist_ok=True)
    # Clear previous events
    if _ghidra_init_events.exists():
        _ghidra_init_events.unlink()

    loop = asyncio.get_event_loop()

    def _init() -> None:
        import io
        import os
        import sys

        t0 = _time.time()

        _emit_ghidra_event({"t": "log", "msg": "checking ghidra installation..."})

        ghidra_home = os.environ.get("DAYWATER_GHIDRA_HOME", "")
        if not ghidra_home or not Path(ghidra_home).exists():
            _emit_ghidra_event({
                "t": "error",
                "msg": f"DAYWATER_GHIDRA_HOME not set or missing: {ghidra_home!r}",
            })
            _emit_ghidra_event({"t": "done", "ok": False})
            return

        _emit_ghidra_event({"t": "log", "msg": f"ghidra home: {ghidra_home}"})

        # Check for GameCubeLoader extension
        ext_dir = Path(ghidra_home) / "Ghidra" / "Extensions" / "GameCubeLoader"
        if ext_dir.exists():
            _emit_ghidra_event({"t": "log", "msg": "gamecubeloader extension found"})
        else:
            _emit_ghidra_event({"t": "log", "msg": "WARNING: GameCubeLoader extension not found"})

        # Check SLEIGH compiled specs
        gekko_sla = ext_dir / "data" / "languages" / "ppc_gekko_broadway.sla"
        if gekko_sla.exists():
            _emit_ghidra_event({"t": "log", "msg": "gekko/broadway SLEIGH specs compiled"})
        else:
            _emit_ghidra_event({"t": "log", "msg": "WARNING: gekko SLEIGH .sla missing — analysis may fail"})

        _emit_ghidra_event({"t": "phase", "phase": "jvm_start", "msg": "starting JVM..."})

        # Capture JVM stdout/stderr during startup
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        capture_buf = io.StringIO()

        class TeeWriter:
            """Write to both capture buffer and emit events for each line."""

            def __init__(self, original: Any, label: str) -> None:
                self.original = original
                self.label = label
                self.buf = ""

            def write(self, s: str) -> int:
                self.original.write(s)
                self.buf += s
                while "\n" in self.buf:
                    line, self.buf = self.buf.split("\n", 1)
                    line = line.strip()
                    if line:
                        _emit_ghidra_event({"t": "jvm_log", "msg": line})
                return len(s)

            def flush(self) -> None:
                self.original.flush()
                if self.buf.strip():
                    _emit_ghidra_event({"t": "jvm_log", "msg": self.buf.strip()})
                    self.buf = ""

        sys.stdout = TeeWriter(old_stdout, "stdout")  # type: ignore[assignment]
        sys.stderr = TeeWriter(old_stderr, "stderr")  # type: ignore[assignment]

        try:
            import pyghidra

            pyghidra.start()
        except Exception as exc:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            _emit_ghidra_event({"t": "error", "msg": f"JVM start failed: {exc}"})
            _emit_ghidra_event({"t": "done", "ok": False})
            return
        finally:
            # Flush remaining buffered output
            if hasattr(sys.stdout, "flush"):
                sys.stdout.flush()
            if hasattr(sys.stderr, "flush"):
                sys.stderr.flush()
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        jvm_elapsed = _time.time() - t0
        _emit_ghidra_event({
            "t": "phase",
            "phase": "jvm_ready",
            "msg": f"JVM ready ({jvm_elapsed:.1f}s)",
        })

        # Verify we can import Ghidra Java classes
        _emit_ghidra_event({"t": "log", "msg": "importing ghidra framework classes..."})
        try:
            from ghidra.app.decompiler import DecompInterface  # noqa: F401
            from ghidra.util.task import ConsoleTaskMonitor  # noqa: F401

            _emit_ghidra_event({"t": "log", "msg": "ghidra framework loaded"})
        except Exception as exc:
            _emit_ghidra_event({"t": "error", "msg": f"failed to import Ghidra classes: {exc}"})
            _emit_ghidra_event({"t": "done", "ok": False})
            return

        # Try a test analysis if a sample binary is available
        sample_dol = Path("/app/samples/nightfire_hud_off/boot.dol")
        # Also check extracted binaries from any existing project
        if not sample_dol.exists():
            extracted = _CACHE_ROOT / "extracted"
            if extracted.exists():
                for dol in extracted.rglob("boot.dol"):
                    sample_dol = dol
                    break

        if sample_dol.exists():
            _emit_ghidra_event({
                "t": "phase",
                "phase": "analysis_start",
                "msg": f"test analysis: {sample_dol.name}...",
            })
            try:
                from src.ghidra import run_analysis

                result = run_analysis(sample_dol)
                _emit_ghidra_event({
                    "t": "phase",
                    "phase": "analysis_done",
                    "msg": f"analysis complete: {result.function_count:,} functions ({_time.time() - t0:.1f}s total)",
                })
            except Exception as exc:
                _emit_ghidra_event({
                    "t": "log",
                    "msg": f"test analysis failed (non-fatal): {exc}",
                })
        else:
            _emit_ghidra_event({
                "t": "log",
                "msg": "no test binary available — skipping test analysis (will run on first ISO upload)",
            })

        total = _time.time() - t0
        _emit_ghidra_event({
            "t": "done",
            "ok": True,
            "msg": f"initialization complete ({total:.1f}s)",
        })

    try:
        await loop.run_in_executor(_executor, _init)
    except Exception as exc:
        _emit_ghidra_event({"t": "error", "msg": str(exc)})
        _emit_ghidra_event({"t": "done", "ok": False})
    finally:
        _ghidra_init_running = False


async def stream_ghidra_init_events() -> Any:
    """Yield SSE events from the Ghidra init log file."""
    offset = 0
    while True:
        if _ghidra_init_events.exists():
            content = _ghidra_init_events.read_text()
            lines = content.split("\n")
            new_lines = lines[offset:]
            for line in new_lines:
                line = line.strip()
                if line:
                    yield f"data: {line}\n\n"
                    # Check if this is a terminal event
                    try:
                        evt = json.loads(line)
                        if evt.get("t") == "done":
                            return
                    except json.JSONDecodeError:
                        pass
            offset = len(lines)

        yield f"data: {json.dumps({'t': 'heartbeat'})}\n\n"
        await asyncio.sleep(0.5)
