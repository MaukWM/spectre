"""Interactive Dolphin session — boot, send inputs, read memory, terminate.

Wraps the pipe input (``input.py``), process memory reader (``memory.py``),
and MemoryWatcher (``watcher.py``) into a single context-managed session.

Usage::

    with DolphinSession.start(
        iso=iso_path,
        savestate=sav_path,
        gecko_codes=codes,
        pipe_input=True,
        watch_addresses=[x_addr, y_addr, z_addr],
    ) as session:
        session.wait_for_first_frame()
        session.play_sequence(InputSequence.walk_forward(5.0))
        time.sleep(5)
        pos = session.read_position(x_addr, y_addr, z_addr)
        samples = session.get_watcher_samples()
        frames = session.collect_frames(out_dir)
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from src.dolphin.debugger import GDBClient, WriteHit, find_writers
from src.dolphin.gecko import GeckoCode, parse_gecko, render_gecko_ini
from src.dolphin.input import (
    InputSequence,
    play_inputs,
    setup_pipe_input,
)
from src.dolphin.memory import (
    DolphinMemoryError,
    clear_mem1_cache,
    read_gc_bytes,
    read_gc_float,
    read_gc_floats,
    read_gc_u32,
)
from src.dolphin.runner import (
    DEFAULT_DOLPHIN_INI,
    DEFAULT_GFX_INI,
    VideoBackend,
    _find_linux_dolphin,
    check_savestate_compatibility,
    collect_dump,
)
from src.dolphin.watcher import (
    MemoryWatcherListener,
    PositionSample,
    create_watcher_socket,
    write_locations_file,
)
from src.logging import logger

_IS_LINUX = sys.platform == "linux"


def _find_dolphin_child_pid(parent_pid: int, timeout: float = 15.0) -> int:
    """Find the actual dolphin-emu PID when launched via xvfb-run.

    xvfb-run spawns Xvfb + dolphin-emu as descendants. We walk /proc
    to find any process whose cmdline contains 'dolphin-emu' that is
    a descendant of parent_pid. Falls back to parent_pid if not found.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            # Build pid -> ppid map
            pid_to_ppid: dict[int, int] = {}
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                try:
                    status = (entry / "status").read_text()
                    for line in status.splitlines():
                        if line.startswith("PPid:"):
                            pid_to_ppid[pid] = int(line.split(":")[1].strip())
                            break
                except (OSError, ValueError):
                    continue

            # Find descendants of parent_pid
            def is_descendant(pid: int) -> bool:
                visited: set[int] = set()
                while pid in pid_to_ppid and pid not in visited:
                    visited.add(pid)
                    pid = pid_to_ppid[pid]
                    if pid == parent_pid:
                        return True
                return False

            for pid in pid_to_ppid:
                if pid == parent_pid:
                    continue
                if not is_descendant(pid):
                    continue
                try:
                    cmdline = (Path(f"/proc/{pid}") / "cmdline").read_bytes()
                    if b"dolphin-emu" in cmdline:
                        logger.info(
                            "dolphin_child_found",
                            parent=parent_pid,
                            child=pid,
                        )
                        return pid
                except OSError:
                    continue
        except OSError:
            pass
        time.sleep(0.5)

    logger.warning("dolphin_child_not_found", parent=parent_pid)
    return parent_pid


@dataclass
class DolphinSession:
    """Handle to a running Dolphin instance with input + memory capabilities."""

    proc: subprocess.Popen[bytes]
    pid: int
    user_dir: Path
    pipe_path: Path | None = None
    _watcher: MemoryWatcherListener | None = None
    _gdb: GDBClient | None = None
    _tmp_root: Path | None = None  # for cleanup
    _input_thread: threading.Thread | None = field(default=None, repr=False)

    # --- Memory reads (dynamic, any address) ------------------------------ #

    def read_float(self, gc_address: int) -> float:
        """Read a big-endian float from a GameCube address."""
        return read_gc_float(self.pid, gc_address)

    def read_u32(self, gc_address: int) -> int:
        """Read a big-endian u32 from a GameCube address."""
        return read_gc_u32(self.pid, gc_address)

    def read_bytes(self, gc_address: int, size: int) -> bytes:
        """Read raw bytes from a GameCube address."""
        return read_gc_bytes(self.pid, gc_address, size)

    def read_floats(self, addresses: list[int]) -> list[float]:
        """Read multiple big-endian floats, one per address."""
        return read_gc_floats(self.pid, addresses)

    def read_position(
        self, x_addr: int, y_addr: int, z_addr: int
    ) -> tuple[float, float, float]:
        """Read X/Y/Z position as a float triple."""
        return (
            self.read_float(x_addr),
            self.read_float(y_addr),
            self.read_float(z_addr),
        )

    def sample_position_over_time(
        self,
        x_addr: int,
        y_addr: int,
        z_addr: int,
        duration: float,
        interval: float = 0.5,
    ) -> list[PositionSample]:
        """Poll position at *interval* for *duration* seconds via process memory.

        Returns a time series of PositionSample values.
        """
        samples: list[PositionSample] = []
        t0 = time.monotonic()
        deadline = t0 + duration

        while time.monotonic() < deadline:
            try:
                x, y, z = self.read_position(x_addr, y_addr, z_addr)
                samples.append(
                    PositionSample(
                        x=x, y=y, z=z, timestamp=time.monotonic() - t0
                    )
                )
            except DolphinMemoryError:
                pass  # process may not be ready yet
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(interval, remaining))

        return samples

    # --- MemoryWatcher reads (known addresses, continuous) ---------------- #

    def get_watcher_samples(self) -> list[PositionSample]:
        """Drain and return all MemoryWatcher position samples."""
        if self._watcher is None:
            return []
        return self._watcher.drain()

    def get_watcher_latest(self) -> tuple[float, float, float] | None:
        """Return the latest position from MemoryWatcher, or None."""
        if self._watcher is None:
            return None
        self._watcher.drain()
        return self._watcher.get_latest_position()

    # --- GDB debugger (write watchpoints) -------------------------------- #

    def find_writers(
        self,
        address: int,
        *,
        size: int = 4,
        duration: float = 3.0,
        max_hits: int = 200,
    ) -> list[WriteHit]:
        """Find all instructions that write to a GameCube address.

        Uses the GDB stub's hardware write watchpoints. Session must have
        been started with ``gdb_port`` set.
        """
        if self._gdb is None:
            raise RuntimeError(
                "Session was started without gdb_port — cannot use find_writers"
            )
        return find_writers(
            self._gdb,
            address,
            size=size,
            duration=duration,
            max_hits=max_hits,
        )

    # --- Input ------------------------------------------------------------ #

    def send_input(self, command: str) -> None:
        """Send a single pipe command (e.g. 'PRESS A') to Dolphin."""
        if self.pipe_path is None:
            raise RuntimeError("Session was started without pipe_input=True")
        fd = os.open(str(self.pipe_path), os.O_WRONLY | os.O_NONBLOCK)
        try:
            os.write(fd, (command + "\n").encode("ascii"))
        finally:
            os.close(fd)

    def play_sequence(self, sequence: InputSequence) -> None:
        """Play an input sequence on the pipe (blocks for its duration)."""
        if self.pipe_path is None:
            raise RuntimeError("Session was started without pipe_input=True")
        play_inputs(self.pipe_path, sequence)

    def play_sequence_async(self, sequence: InputSequence) -> None:
        """Play an input sequence in a background thread (non-blocking)."""
        if self.pipe_path is None:
            raise RuntimeError("Session was started without pipe_input=True")
        self._input_thread = threading.Thread(
            target=play_inputs,
            args=(self.pipe_path, sequence),
            daemon=True,
        )
        self._input_thread.start()

    # --- Frame management ------------------------------------------------- #

    def wait_for_first_frame(self, timeout: float = 30.0) -> bool:
        """Poll until Dolphin dumps at least one frame PNG.

        Returns True if a frame appeared, False on timeout. Ensures the
        savestate has loaded and the game is rendering before we send inputs
        or read memory.
        """
        frames_dir = self.user_dir / "Dump" / "Frames"
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                logger.warning("dolphin_exited_early", rc=self.proc.returncode)
                return False
            pngs = list(frames_dir.glob("*.png"))
            if pngs:
                logger.debug("first_frame_detected", count=len(pngs))
                return True
            time.sleep(0.25)

        logger.warning("first_frame_timeout", timeout=timeout)
        return False

    def collect_frames(self, out_dir: Path) -> list[Path]:
        """Copy dumped frames to *out_dir*."""
        return collect_dump(self.user_dir, out_dir)

    # --- Lifecycle -------------------------------------------------------- #

    def is_running(self) -> bool:
        """Check if Dolphin is still running."""
        return self.proc.poll() is None

    def terminate(self, timeout: float = 10.0) -> int:
        """Send SIGTERM, wait, escalate to SIGKILL if needed.

        Returns the process exit code.
        """
        if self.proc.poll() is not None:
            rc = self.proc.returncode
        else:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
            rc = self.proc.returncode if self.proc.returncode is not None else -1

        # Wait for input thread to finish
        if self._input_thread is not None and self._input_thread.is_alive():
            self._input_thread.join(timeout=2)

        # Close GDB connection
        if self._gdb is not None:
            self._gdb.close()

        # Close watcher socket
        if self._watcher is not None:
            self._watcher.close()

        # Clear memory cache for this pid
        clear_mem1_cache(self.pid)

        logger.info("dolphin_session_terminated", pid=self.pid, rc=rc)
        return rc

    def cleanup(self) -> None:
        """Remove the temporary directory if one was auto-created."""
        if self._tmp_root is not None:
            shutil.rmtree(self._tmp_root, ignore_errors=True)

    # --- Factory ---------------------------------------------------------- #

    @classmethod
    @contextmanager
    def start(
        cls,
        iso: Path,
        *,
        savestate: Path | None = None,
        gecko_codes: list[GeckoCode] | None = None,
        gecko_text: str = "",
        pipe_input: bool = False,
        watch_addresses: list[int] | None = None,
        gdb_port: int | None = None,
        video_backend: VideoBackend = "Software",
        run_seconds: int | None = None,
        user_dir: Path | None = None,
    ) -> Iterator[DolphinSession]:
        """Context manager that boots Dolphin and yields a session handle.

        Args:
            iso: Path to the GameCube ISO.
            savestate: Optional savestate to load on boot.
            gecko_codes: Parsed GeckoCode objects to inject.
            gecko_text: Raw gecko text (parsed if gecko_codes is None).
            pipe_input: Enable named pipe controller input.
            watch_addresses: GC addresses for MemoryWatcher monitoring.
            gdb_port: Enable GDB stub on this TCP port (for write watchpoints).
            video_backend: Dolphin video backend.
            run_seconds: If set, auto-terminate after this many seconds.
            user_dir: Custom user dir (auto-created in temp if None).
        """
        if savestate is not None:
            check_savestate_compatibility(savestate)

        # Resolve gecko codes
        codes = gecko_codes or (parse_gecko(gecko_text) if gecko_text else [])

        # Set up user directory
        tmp_root: Path | None = None
        if user_dir is None:
            tmp_root = Path(tempfile.mkdtemp(prefix="spectre_session_"))
            user_dir = tmp_root / "user"

        # Read game ID for INI file naming
        from src.dolphin.runner import read_game_id

        game_id = read_game_id(iso)

        # Write base config
        (user_dir / "Config").mkdir(parents=True, exist_ok=True)
        (user_dir / "GameSettings").mkdir(parents=True, exist_ok=True)
        (user_dir / "Dump" / "Frames").mkdir(parents=True, exist_ok=True)

        dolphin_ini = DEFAULT_DOLPHIN_INI
        if gdb_port is not None:
            # Inject GDB stub config — Dolphin reads GDBPort from [General]
            dolphin_ini = dolphin_ini.replace(
                "[General]\n",
                f"[General]\nGDBPort = {gdb_port}\n",
            )
        (user_dir / "Config" / "Dolphin.ini").write_text(dolphin_ini)
        (user_dir / "Config" / "GFX.ini").write_text(DEFAULT_GFX_INI)

        ini_text = render_gecko_ini(codes)
        if ini_text:
            (user_dir / "GameSettings" / f"{game_id}.ini").write_text(ini_text)

        # Set up pipe input
        pipe_path: Path | None = None
        if pipe_input:
            pipe_path = setup_pipe_input(user_dir)

        # Set up MemoryWatcher
        watcher: MemoryWatcherListener | None = None
        if watch_addresses:
            write_locations_file(user_dir, watch_addresses)
            sock = create_watcher_socket(user_dir)
            # We'll create the listener after we know addresses
            # (x, y, z order from watch_addresses)
            if len(watch_addresses) >= 3:
                watcher = MemoryWatcherListener(
                    sock=sock,
                    x_addr=watch_addresses[0],
                    y_addr=watch_addresses[1],
                    z_addr=watch_addresses[2],
                )

        # Build Dolphin command
        if not _IS_LINUX:
            raise RuntimeError(
                "DolphinSession currently supports Linux only. "
                "Use run_dolphin() for macOS."
            )

        dolphin_bin = _find_linux_dolphin()
        dolphin_args = [
            dolphin_bin,
            f"-u{user_dir}",
            f"-v{video_backend}",
            f"-e{iso}",
            "-CMovie.DumpFramesAsImages=True",
        ]
        if not os.environ.get("DISPLAY") and shutil.which("xvfb-run"):
            dolphin_args = [
                "xvfb-run", "-a", "-s", "-screen 0 640x480x24",
                *dolphin_args,
            ]
        elif dolphin_bin.endswith("dolphin-emu-nogui"):
            dolphin_args.insert(1, "-pheadless")

        if savestate is not None:
            dolphin_args.append(f"-s{savestate}")

        # Launch
        env = os.environ.copy()
        env.setdefault("LC_ALL", "en_US.UTF-8")

        log_path = (tmp_root or user_dir) / "dolphin.log"
        logf = log_path.open("wb")

        proc = subprocess.Popen(
            dolphin_args,
            stdout=logf,
            stderr=subprocess.STDOUT,
            env=env,
        )

        logger.info(
            "dolphin_session_started",
            pid=proc.pid,
            pipe=pipe_input,
            watcher=bool(watch_addresses),
            gdb=gdb_port,
            gecko_codes=len(codes),
        )

        # Connect GDB stub if enabled.
        # NOTE: Dolphin starts with the CPU PAUSED when GDB is on.
        # We continue immediately so the savestate loads and the game
        # runs. The find_writers() method will interrupt when it needs to.
        gdb_client: GDBClient | None = None
        if gdb_port is not None:
            gdb_client = GDBClient(port=gdb_port)
            gdb_client.connect(timeout=15.0)
            # Continue execution and consume the ACK
            gdb_client.continue_execution()
            # Drain any pending ACK so the socket is clean
            time.sleep(0.2)
            gdb_client._drain_pending()
            logger.info("gdb_stub_connected", port=gdb_port)

        # When launched via xvfb-run, proc.pid is xvfb-run, not dolphin.
        # Find the real dolphin PID for memory reads.
        dolphin_pid = proc.pid
        if dolphin_args[0] == "xvfb-run":
            dolphin_pid = _find_dolphin_child_pid(proc.pid)

        session = cls(
            proc=proc,
            pid=dolphin_pid,
            user_dir=user_dir,
            pipe_path=pipe_path,
            _watcher=watcher,
            _gdb=gdb_client,
            _tmp_root=tmp_root,
        )

        try:
            yield session
        finally:
            if session.is_running():
                session.terminate()
            logf.close()
            session.cleanup()
