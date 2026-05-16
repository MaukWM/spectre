"""Pipe-based controller input injection for Dolphin.

Dolphin reads named pipe commands every frame via GCPadNew.ini config.
Protocol (from Dolphin source ``Pipes.cpp``):

    PRESS A\\n          — button down (A, B, X, Y, Z, START, L, R, D_UP, etc.)
    RELEASE A\\n        — button up
    SET MAIN 0.5 0.0\\n — main stick (x, y) where 0.5 = centre, 0.0/1.0 = extremes
    SET C 0.5 0.5\\n    — C-stick
    SET L 1.0\\n        — left trigger (0.0–1.0)

Stick axis mapping: 0.0 = full negative, 0.5 = neutral, 1.0 = full positive.
Internally Dolphin splits each axis into +/- halves.

The named pipe (FIFO) must exist before Dolphin starts. Dolphin opens it with
O_RDONLY | O_NONBLOCK — it won't block waiting for a writer. The writer must
keep the fd open for the session duration (closing triggers EOF).
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from src.logging import logger

# --- GCPadNew.ini template ------------------------------------------------ #

GCPAD_INI_TEMPLATE = """\
[GCPad1]
Device = Pipe/0/{pipe_name}
Buttons/A = `Button A`
Buttons/B = `Button B`
Buttons/X = `Button X`
Buttons/Y = `Button Y`
Buttons/Z = `Button Z`
Buttons/Start = `Button START`
D-Pad/Up = `Button D_UP`
D-Pad/Down = `Button D_DOWN`
D-Pad/Left = `Button D_LEFT`
D-Pad/Right = `Button D_RIGHT`
Triggers/L = `Button L`
Triggers/R = `Button R`
Main Stick/Up = `Axis MAIN Y -`
Main Stick/Down = `Axis MAIN Y +`
Main Stick/Left = `Axis MAIN X -`
Main Stick/Right = `Axis MAIN X +`
C-Stick/Up = `Axis C Y -`
C-Stick/Down = `Axis C Y +`
C-Stick/Left = `Axis C X -`
C-Stick/Right = `Axis C X +`
"""

DEFAULT_PIPE_NAME = "spectre"


# --- Input sequence data model -------------------------------------------- #


@dataclass(frozen=True)
class InputCommand:
    """A single pipe command to send at a given time offset."""

    time_offset: float  # seconds from start of sequence
    command: str  # e.g. "SET MAIN 0.5 0.0" (no trailing newline)


@dataclass(frozen=True)
class InputSequence:
    """Timestamped list of Dolphin pipe commands forming a complete input plan."""

    commands: list[InputCommand] = field(default_factory=list)

    @classmethod
    def stand_still(cls, duration: float) -> InputSequence:
        """Neutral stick for *duration* seconds. Useful as a control test."""
        return cls(
            commands=[
                InputCommand(0.0, "SET MAIN 0.5 0.5"),
                InputCommand(duration, "SET MAIN 0.5 0.5"),
            ]
        )

    @classmethod
    def walk_forward(cls, duration: float) -> InputSequence:
        """Hold main stick fully forward for *duration* seconds.

        Stick Y = 0.0 maps to "up" in Dolphin's pipe protocol (full negative
        on the Y axis = forward in most games).
        """
        return cls(
            commands=[
                InputCommand(0.0, "SET MAIN 0.5 0.0"),
                InputCommand(duration, "SET MAIN 0.5 0.5"),
            ]
        )

    @classmethod
    def jump(cls, duration: float = 3.0) -> InputSequence:
        """Tap A button (jump in most games), then wait."""
        return cls(
            commands=[
                InputCommand(0.0, "PRESS A"),
                InputCommand(0.3, "RELEASE A"),
                InputCommand(duration, "SET MAIN 0.5 0.5"),
            ]
        )

    @classmethod
    def walk_forward_and_jump(cls, duration: float = 5.0) -> InputSequence:
        """Walk forward and jump midway through."""
        return cls(
            commands=[
                InputCommand(0.0, "SET MAIN 0.5 0.0"),
                InputCommand(1.0, "PRESS A"),
                InputCommand(1.3, "RELEASE A"),
                InputCommand(duration, "SET MAIN 0.5 0.5"),
            ]
        )

    @classmethod
    def walk_backward(cls, duration: float) -> InputSequence:
        """Hold main stick fully backward for *duration* seconds.

        Stick Y = 1.0 maps to "down" in Dolphin's pipe protocol (full positive
        on the Y axis = backward in most games).
        """
        return cls(
            commands=[
                InputCommand(0.0, "SET MAIN 0.5 1.0"),
                InputCommand(duration, "SET MAIN 0.5 0.5"),
            ]
        )

    @classmethod
    def strafe_left(cls, duration: float) -> InputSequence:
        """Hold main stick fully left for *duration* seconds."""
        return cls(
            commands=[
                InputCommand(0.0, "SET MAIN 0.0 0.5"),
                InputCommand(duration, "SET MAIN 0.5 0.5"),
            ]
        )

    @classmethod
    def strafe_right(cls, duration: float) -> InputSequence:
        """Hold main stick fully right for *duration* seconds."""
        return cls(
            commands=[
                InputCommand(0.0, "SET MAIN 1.0 0.5"),
                InputCommand(duration, "SET MAIN 0.5 0.5"),
            ]
        )

    @classmethod
    def look_up(cls, duration: float) -> InputSequence:
        """Hold C-stick up for *duration* seconds (camera/aim up)."""
        return cls(
            commands=[
                InputCommand(0.0, "SET C 0.5 0.0"),
                InputCommand(duration, "SET C 0.5 0.5"),
            ]
        )

    @classmethod
    def look_down(cls, duration: float) -> InputSequence:
        """Hold C-stick down for *duration* seconds (camera/aim down)."""
        return cls(
            commands=[
                InputCommand(0.0, "SET C 0.5 1.0"),
                InputCommand(duration, "SET C 0.5 0.5"),
            ]
        )

    @classmethod
    def from_preset(cls, name: str, duration: float = 5.0) -> InputSequence:
        """Look up a named preset. Raises ValueError for unknown names."""
        presets: dict[str, Callable[..., InputSequence]] = {
            "stand_still": cls.stand_still,
            "walk_forward": cls.walk_forward,
            "walk_backward": cls.walk_backward,
            "strafe_left": cls.strafe_left,
            "strafe_right": cls.strafe_right,
            "jump": cls.jump,
            "walk_forward_and_jump": cls.walk_forward_and_jump,
            "look_up": cls.look_up,
            "look_down": cls.look_down,
        }
        factory = presets.get(name)
        if factory is None:
            raise ValueError(
                f"Unknown input preset {name!r}. "
                f"Available: {', '.join(sorted(presets))}"
            )
        return factory(duration)


# --- FIFO + config file management ---------------------------------------- #

PRESET_NAMES = [
    "stand_still", "walk_forward", "walk_backward",
    "strafe_left", "strafe_right",
    "jump", "walk_forward_and_jump",
    "look_up", "look_down",
]


def setup_pipe_input(
    user_dir: Path, pipe_name: str = DEFAULT_PIPE_NAME
) -> Path:
    """Write GCPadNew.ini and create the named FIFO for pipe input.

    Must be called before Dolphin starts.

    Returns the FIFO path (caller opens it for writing after Dolphin boots).
    """
    # Write GCPad config
    config_dir = user_dir / "Config"
    config_dir.mkdir(parents=True, exist_ok=True)
    gcpad_path = config_dir / "GCPadNew.ini"
    gcpad_path.write_text(GCPAD_INI_TEMPLATE.format(pipe_name=pipe_name))

    # Create FIFO
    pipes_dir = user_dir / "Pipes"
    pipes_dir.mkdir(parents=True, exist_ok=True)
    fifo_path = pipes_dir / pipe_name

    if fifo_path.exists():
        fifo_path.unlink()
    os.mkfifo(fifo_path)

    logger.debug("pipe_input_setup", fifo=str(fifo_path), config=str(gcpad_path))
    return fifo_path


def play_inputs(fifo_path: Path, sequence: InputSequence) -> None:
    """Send an input sequence to Dolphin via the named pipe.

    Opens the FIFO for writing, sends commands at their scheduled times,
    then closes. The caller should ensure Dolphin is running and has loaded
    the game before calling this (otherwise inputs are buffered but may be
    consumed before the game is ready).

    This function blocks for the duration of the sequence.
    """
    if not sequence.commands:
        return

    if not fifo_path.exists() or not stat.S_ISFIFO(fifo_path.stat().st_mode):
        raise FileNotFoundError(f"FIFO not found at {fifo_path}")

    # Sort commands by time
    sorted_cmds = sorted(sequence.commands, key=lambda c: c.time_offset)
    total_duration = sorted_cmds[-1].time_offset

    logger.info(
        "pipe_input_play",
        commands=len(sorted_cmds),
        duration=round(total_duration, 2),
    )

    # Open FIFO for writing. Without O_NONBLOCK this blocks until Dolphin
    # opens the read end (which happens at controller-init time).
    # We retry with a timeout in case Dolphin hasn't scanned Pipes/ yet.
    fd = -1
    open_deadline = time.monotonic() + 15.0
    while time.monotonic() < open_deadline:
        try:
            fd = os.open(str(fifo_path), os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError:
            time.sleep(0.25)
    if fd < 0:
        # Last attempt without O_NONBLOCK (blocks until reader appears)
        fd = os.open(str(fifo_path), os.O_WRONLY)
    try:
        t0 = time.monotonic()
        for cmd in sorted_cmds:
            # Wait until it's time to send this command
            target_time = t0 + cmd.time_offset
            now = time.monotonic()
            if target_time > now:
                time.sleep(target_time - now)

            line = cmd.command + "\n"
            try:
                os.write(fd, line.encode("ascii"))
            except BrokenPipeError:
                logger.debug("pipe_input_broken", msg="Dolphin closed the pipe")
                break
    finally:
        os.close(fd)

    logger.debug("pipe_input_done")
