"""Agent tools for runtime Dolphin interaction (memory reads, input, scanning).

These tools wrap a live DolphinSession and are used by tasks that need runtime
access (position discovery, noclip). Each tool is a closure capturing the
session reference.

For noclip tasks, tools bind to a ``SessionRef`` instead of a raw session.
``SessionRef`` is a mutable proxy — when ``apply_gecko_code`` reboots Dolphin,
all tools transparently see the new session.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

from inspect_ai.tool import Tool, tool

from src.dolphin.input import InputCommand, InputSequence
from src.dolphin.memory import scan_floats_in_range
from src.dolphin.session import DolphinSession
from src.findings import FindingsStore
from src.logging import logger


class SessionRef:
    """Mutable proxy to a :class:`DolphinSession`.

    Attribute access is forwarded to the underlying session so existing tools
    (which expect ``DolphinSession``) work without changes.  The noclip task
    calls :meth:`swap` when it reboots Dolphin with new Gecko codes.
    """

    def __init__(self, session: DolphinSession) -> None:
        # Store in object __dict__ directly to avoid __getattr__ recursion.
        object.__setattr__(self, "_session", session)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_session"), name)

    @property
    def session(self) -> DolphinSession:
        return object.__getattribute__(self, "_session")

    def swap(self, new_session: DolphinSession) -> None:
        object.__setattr__(self, "_session", new_session)


# Valid GC buttons for the pipe protocol.
GC_BUTTONS = frozenset(
    {
        "A",
        "B",
        "X",
        "Y",
        "Z",
        "START",
        "L",
        "R",
        "D_UP",
        "D_DOWN",
        "D_LEFT",
        "D_RIGHT",
    }
)

# Valid stick names.
GC_STICKS = frozenset({"MAIN", "C"})


# ── Memory reading tools ──────────────────────────────────────────────── #


@tool
def read_memory(session: DolphinSession) -> Tool:
    """Build a memory read tool bound to a DolphinSession."""

    async def execute(address: str, format: str = "f32") -> str:
        """Read a value from GameCube memory at a hex address.

        Args:
            address: Hex address, e.g. "0x8030FA4C" or "8030FA4C".
            format: Data type to read. One of "f32" (big-endian float),
                "u32" (big-endian unsigned 32-bit int), "u8" (single byte).
        """
        try:
            gc_addr = int(address, 16)
        except ValueError:
            return f"Error: invalid hex address '{address}'"

        try:
            if format == "f32":
                val = session.read_float(gc_addr)
                return f"0x{gc_addr:08X} = {val:.6f} (f32)"
            elif format == "u32":
                val = session.read_u32(gc_addr)
                return f"0x{gc_addr:08X} = {val} (0x{val:08X}) (u32)"
            elif format == "u8":
                raw = session.read_bytes(gc_addr, 1)
                return f"0x{gc_addr:08X} = {raw[0]} (0x{raw[0]:02X}) (u8)"
            else:
                return f"Error: unknown format '{format}'. Use 'f32', 'u32', or 'u8'."
        except Exception as e:
            return f"Error reading 0x{gc_addr:08X}: {e}"

    return execute


@tool
def read_memory_batch(session: DolphinSession) -> Tool:
    """Build a batch memory read tool bound to a DolphinSession."""

    async def execute(addresses: str, format: str = "f32") -> str:
        """Read multiple GameCube memory addresses at once.

        Args:
            addresses: Comma-separated hex addresses, e.g.
                "0x8030FA4C, 0x8030FA50, 0x8030FA54".
            format: Data type — "f32" or "u32". Applied to all addresses.
        """
        addr_strs = [a.strip() for a in addresses.split(",") if a.strip()]
        if not addr_strs:
            return "Error: no addresses provided."
        if len(addr_strs) > 50:
            return "Error: max 50 addresses per batch."

        lines = []
        for addr_str in addr_strs:
            try:
                gc_addr = int(addr_str, 16)
            except ValueError:
                lines.append(f"  {addr_str}: invalid hex")
                continue
            try:
                if format == "f32":
                    val = session.read_float(gc_addr)
                    lines.append(f"  0x{gc_addr:08X} = {val:.6f}")
                else:
                    val = session.read_u32(gc_addr)
                    lines.append(f"  0x{gc_addr:08X} = {val} (0x{val:08X})")
            except Exception as e:
                lines.append(f"  0x{gc_addr:08X}: error — {e}")

        return f"Read {len(addr_strs)} addresses ({format}):\n" + "\n".join(lines)

    return execute


# ── Memory scanning tool ──────────────────────────────────────────────── #


@tool
def scan_memory(session: DolphinSession) -> Tool:
    """Build a memory scanning tool bound to a DolphinSession."""

    async def execute(
        start: str = "0x80000000",
        end: str = "0x81800000",
        min_abs: float = 0.1,
        max_abs: float = 50000.0,
    ) -> str:
        """Scan GameCube memory for plausible float values (position candidates).

        Scans the given address range for 4-byte-aligned big-endian floats
        that are finite, nonzero, and within the absolute value bounds.
        This is useful for finding position, velocity, or other game state.

        Warning: scanning the full MEM1 range (~24 MB) takes several seconds.
        Use a narrower range if you have a hypothesis about where the data lives.

        Args:
            start: Start of scan range as hex (default: 0x80000000 = MEM1 start).
            end: End of scan range as hex (default: 0x81800000 = MEM1 end).
            min_abs: Minimum absolute float value to include (default: 0.1).
            max_abs: Maximum absolute float value to include (default: 50000.0).
        """
        try:
            gc_start = int(start, 16)
            gc_end = int(end, 16)
        except ValueError:
            return "Error: start and end must be hex addresses."

        if gc_end - gc_start > 0x02000000:
            return "Error: scan range too large (max 32 MB). Narrow your range."

        try:
            results = scan_floats_in_range(
                session.pid,
                gc_start,
                gc_end,
                min_abs=min_abs,
                max_abs=max_abs,
            )
        except Exception as e:
            return f"Error during scan: {e}"

        count = len(results)
        if count == 0:
            return f"No plausible floats found in 0x{gc_start:08X}–0x{gc_end:08X}."

        # Return summary + first 100 entries sorted by address
        sorted_addrs = sorted(results.keys())
        sample = sorted_addrs[:100]
        lines = [f"Found {count} plausible floats in 0x{gc_start:08X}–0x{gc_end:08X}:"]
        for addr in sample:
            lines.append(f"  0x{addr:08X} = {results[addr]:.4f}")
        if count > 100:
            lines.append(f"  ... and {count - 100} more (narrow range to see all)")
        return "\n".join(lines)

    return execute


# ── Differential scan tool ────────────────────────────────────────────── #


@tool
def scan_memory_diff(session: DolphinSession) -> Tool:
    """Build a differential memory scan tool bound to a DolphinSession."""

    # Store the last scan result for diffing
    _last_scan: dict[int, float] = {}

    async def execute(
        start: str = "0x80000000",
        end: str = "0x81800000",
        min_delta: float = 0.5,
        max_delta: float = 500.0,
    ) -> str:
        """Scan memory and compare against the previous scan to find changed values.

        Call this twice: once before sending input, once after. The second call
        shows which float addresses changed, helping identify position data.

        Only addresses present in both scans with a delta in [min_delta, max_delta]
        are returned. This filters out frame counters (huge delta) and static data
        (zero delta).

        Args:
            start: Start of scan range as hex.
            end: End of scan range as hex.
            min_delta: Minimum absolute change to report (default: 0.5).
            max_delta: Maximum absolute change to report (default: 500.0).
        """
        try:
            gc_start = int(start, 16)
            gc_end = int(end, 16)
        except ValueError:
            return "Error: start and end must be hex addresses."

        if gc_end - gc_start > 0x02000000:
            return "Error: scan range too large (max 32 MB)."

        try:
            current = scan_floats_in_range(session.pid, gc_start, gc_end)
        except Exception as e:
            return f"Error during scan: {e}"

        if not _last_scan:
            _last_scan.update(current)
            return (
                f"Baseline scan captured: {len(current)} floats in "
                f"0x{gc_start:08X}–0x{gc_end:08X}.\n"
                f"Now send input (e.g. walk_forward), then call scan_memory_diff "
                f"again to see what changed."
            )

        # Compute diffs
        changed: list[tuple[int, float, float, float]] = []
        for addr in sorted(_last_scan.keys()):
            if addr not in current:
                continue
            old_val = _last_scan[addr]
            new_val = current[addr]
            delta = abs(new_val - old_val)
            if min_delta <= delta <= max_delta:
                changed.append((addr, old_val, new_val, delta))

        # Update stored scan
        _last_scan.clear()
        _last_scan.update(current)

        if not changed:
            return (
                f"No addresses changed by [{min_delta}, {max_delta}] delta. "
                f"Try adjusting thresholds or sending different input."
            )

        # Sort by delta descending, show top 50
        changed.sort(key=lambda x: x[3], reverse=True)
        lines = [f"Found {len(changed)} addresses that changed:"]
        for addr, old_v, new_v, delta in changed[:50]:
            lines.append(f"  0x{addr:08X}: {old_v:+.4f} -> {new_v:+.4f} (delta={delta:.4f})")
        if len(changed) > 50:
            lines.append(f"  ... and {len(changed) - 50} more")
        return "\n".join(lines)

    return execute


# ── Input tools (raw GC controller) ───────────────────────────────────── #


@tool
def press_button(session: DolphinSession) -> Tool:
    """Build a button press tool bound to a DolphinSession."""

    async def execute(button: str, duration: float = 0.3) -> str:
        """Press a GameCube controller button for a duration, then release.

        Args:
            button: Button name. One of: A, B, X, Y, Z, START, L, R,
                D_UP, D_DOWN, D_LEFT, D_RIGHT.
            duration: How long to hold the button in seconds (default: 0.3).
        """
        btn = button.upper().strip()
        if btn not in GC_BUTTONS:
            return f"Error: unknown button '{btn}'. Valid: {', '.join(sorted(GC_BUTTONS))}"
        if duration > 15.0:
            return "Error: duration capped at 15 seconds."
        if duration < 0.05:
            return "Error: duration must be at least 0.05 seconds."

        seq = InputSequence(
            commands=[
                InputCommand(0.0, f"PRESS {btn}"),
                InputCommand(duration, f"RELEASE {btn}"),
            ]
        )
        try:
            session.play_sequence(seq)
        except Exception as e:
            return f"Error: {e}"

        return f"Pressed {btn} for {duration:.2f}s."

    return execute


@tool
def set_stick(session: DolphinSession) -> Tool:
    """Build a stick position tool bound to a DolphinSession."""

    async def execute(
        stick: str = "MAIN",
        x: float = 0.5,
        y: float = 0.5,
        duration: float = 3.0,
    ) -> str:
        """Hold a GameCube analog stick at a position, then return to neutral.

        The stick axes range from 0.0 to 1.0, where 0.5 is neutral (center).

        For the MAIN stick:
          - x=0.0 is full left, x=1.0 is full right
          - y=0.0 is full up/forward, y=1.0 is full down/backward

        For the C stick (camera):
          - Same axis mapping as MAIN

        Args:
            stick: "MAIN" for the main analog stick, "C" for the C-stick.
            x: Horizontal position 0.0–1.0 (0.5 = neutral).
            y: Vertical position 0.0–1.0 (0.5 = neutral).
            duration: How long to hold this position in seconds (default: 3.0).
        """
        stick_name = stick.upper().strip()
        if stick_name not in GC_STICKS:
            return f"Error: unknown stick '{stick_name}'. Valid: MAIN, C"
        if duration > 15.0:
            return "Error: duration capped at 15 seconds."
        if duration < 0.1:
            return "Error: duration must be at least 0.1 seconds."
        if not (0.0 <= x <= 1.0 and 0.0 <= y <= 1.0):
            return "Error: x and y must be in range 0.0–1.0."

        seq = InputSequence(
            commands=[
                InputCommand(0.0, f"SET {stick_name} {x:.3f} {y:.3f}"),
                InputCommand(duration, f"SET {stick_name} 0.500 0.500"),
            ]
        )
        try:
            session.play_sequence(seq)
        except Exception as e:
            return f"Error: {e}"

        return f"Held {stick_name} stick at ({x:.2f}, {y:.2f}) for {duration:.1f}s."

    return execute


@tool
def wait(session: DolphinSession) -> Tool:
    """Build a wait tool (let the game run with no input)."""

    async def execute(duration: float = 2.0) -> str:
        """Wait for a duration with no controller input. The game continues running.

        Useful to let physics settle after movement, or to observe values at rest.

        Args:
            duration: How long to wait in seconds (default: 2.0).
        """
        if duration > 30.0:
            return "Error: duration capped at 30 seconds."
        if duration < 0.1:
            return "Error: duration must be at least 0.1 seconds."

        time.sleep(duration)
        return f"Waited {duration:.1f}s."

    return execute


# ── Write watchpoint tool ─────────────────────────────────────────────── #


@tool
def find_writers(session: DolphinSession) -> Tool:
    """Build a write-watchpoint tool bound to a DolphinSession."""

    async def execute(address: str, duration: float = 3.0) -> str:
        """Find all code locations that write to a GameCube memory address.

        Sets a hardware write watchpoint via the GDB stub, lets the game run
        for `duration` seconds, and collects every unique program counter (PC)
        that writes to the address. Use this to trace which function is
        responsible for updating a value (e.g. player position).

        After getting the PCs, use `decompile(pc_address)` to see the code
        that writes to this address. This is how you distinguish the
        authoritative source (e.g. player_movement_update writing object+0x24)
        from copies (camera sync, HUD cache, etc.).

        Note: the game pauses briefly during watchpoint setup and on each hit.
        Keep duration short (2-5s) to avoid excessive pauses.

        Args:
            address: Hex address to watch (e.g. "0x80B96E10").
            duration: How long to monitor in seconds (default: 3.0).
        """
        try:
            gc_addr = int(address, 16)
        except ValueError:
            return f"Error: invalid hex address '{address}'"

        if duration > 15.0:
            return "Error: duration capped at 15 seconds."

        if session._gdb is None:
            return "Error: GDB stub not available — session was not started with gdb_port."

        try:
            hits = session.find_writers(gc_addr, duration=duration)
        except Exception as e:
            return f"Error during watchpoint monitoring: {e}"

        if not hits:
            return (
                f"No writes to 0x{gc_addr:08X} observed in {duration:.1f}s. "
                f"Try sending input while monitoring (the address may only be "
                f"written during movement)."
            )

        lines = [f"Found {len(hits)} code locations writing to 0x{gc_addr:08X}:"]
        for hit in sorted(hits, key=lambda h: h.count, reverse=True):
            lines.append(f"  PC=0x{hit.pc:08X}  hits={hit.count}")
        lines.append("")
        lines.append(
            "Use decompile('0x...') on these PCs to see the writing code. "
            "The authoritative position writer is typically in the player "
            "movement/physics function, not a camera sync or HUD copy."
        )
        return "\n".join(lines)

    return execute


# ── Position sampling tool ────────────────────────────────────────────── #


@tool
def sample_position(session: DolphinSession) -> Tool:
    """Build a position sampling tool bound to a DolphinSession."""

    async def execute(
        x_addr: str,
        y_addr: str,
        z_addr: str,
        duration: float = 3.0,
        interval: float = 0.5,
    ) -> str:
        """Poll three memory addresses over time to observe their trajectory.

        Use this to verify candidate position addresses: send input first,
        then sample during movement to see if the values track position.

        Args:
            x_addr: Hex address for X coordinate.
            y_addr: Hex address for Y coordinate.
            z_addr: Hex address for Z coordinate.
            duration: How long to sample in seconds (default: 3.0).
            interval: Polling interval in seconds (default: 0.5).
        """
        try:
            x = int(x_addr, 16)
            y = int(y_addr, 16)
            z = int(z_addr, 16)
        except ValueError:
            return "Error: addresses must be hex."

        if duration > 15.0:
            return "Error: duration capped at 15 seconds."

        samples = session.sample_position_over_time(x, y, z, duration, interval)

        if not samples:
            return "No samples collected — Dolphin may not be running."

        lines = [f"Sampled {len(samples)} points over {duration:.1f}s:"]
        lines.append(f"  {'Time':>6}  {'X':>12}  {'Y':>12}  {'Z':>12}")
        for s in samples:
            lines.append(f"  {s.timestamp:6.2f}  {s.x:12.4f}  {s.y:12.4f}  {s.z:12.4f}")

        # Summary: total displacement
        if len(samples) >= 2:
            dx = samples[-1].x - samples[0].x
            dy = samples[-1].y - samples[0].y
            dz = samples[-1].z - samples[0].z
            lines.append(f"\nTotal displacement: dX={dx:+.4f} dY={dy:+.4f} dZ={dz:+.4f}")

        return "\n".join(lines)

    return execute


# ── Savestate-scoped findings tools ───────────────────────────────────── #


@tool
def save_savestate_finding(savestate_root: Path, task_id: str = "") -> Tool:
    """Build a savestate-scoped finding tool."""

    async def execute(
        kind: str,
        label: str,
        detail: str,
        address: str = "",
    ) -> str:
        """Save a runtime discovery to this savestate's findings.

        These findings are specific to this savestate's memory layout. Use this
        to record exact RAM addresses for player position, velocity, etc.

        Args:
            kind: "address" for memory addresses, "note" for observations.
            label: Short identifier (e.g. "player_x", "player_y", "player_z").
            detail: What this address holds and how you confirmed it.
            address: Hex address (e.g. "8030FA4C"). Required for "address" kind.
        """
        if kind not in ("address", "note"):
            return f"Error: kind must be 'address' or 'note', got '{kind}'"
        if kind == "address" and not address.strip():
            return "Error: address findings require an address."
        if not label.strip():
            return "Error: label is required."

        store = FindingsStore.load(savestate_root)
        finding = store.add(
            kind=kind,
            label=label.strip(),
            detail=detail.strip(),
            address=address.strip(),
            source_task=task_id,
        )
        addr_str = f" @ 0x{finding.address}" if finding.address else ""
        return f"Savestate finding {finding.id} saved: {finding.label}{addr_str}"

    return execute


@tool
def list_savestate_findings(savestate_root: Path) -> Tool:
    """Build a savestate-scoped findings list tool."""

    async def execute() -> str:
        """List all runtime findings saved for this savestate.

        Shows memory addresses and labels discovered during position testing.
        """
        store = FindingsStore.load(savestate_root)
        if not store.findings:
            return "No savestate findings yet."
        return store.format_table()

    return execute


# ── Screenshot helper ────────────────────────────────────────────────── #


def _capture_frame_content(session_ref: SessionRef) -> Any | None:
    """Grab the latest dumped frame from Dolphin as a ContentImage.

    Re-encodes through Pillow to fix truncated/corrupt PNGs that Dolphin's
    Software renderer can produce (frames written mid-render).
    """
    import io

    from inspect_ai.model import ContentImage
    from PIL import Image

    session = session_ref.session
    frames_dir = session.user_dir / "Dump" / "Frames"
    frames = sorted(frames_dir.glob("*.png"))
    if not frames:
        return None
    try:
        img = Image.open(frames[-1])
        img.load()  # force full decode — catches truncated files
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        return ContentImage(image=f"data:image/png;base64,{b64}")
    except Exception:
        logger.warning("frame_capture_failed", path=str(frames[-1]))
        return None


# ── Noclip-specific tools ────────────────────────────────────────────── #


@tool
def capture_screenshot(session_ref: SessionRef) -> Tool:
    """Build a screenshot capture tool bound to a SessionRef."""

    async def execute() -> list[Any] | str:
        """Capture the current Dolphin frame as an image.

        Returns a screenshot of the game's current visual state. Use this
        to visually inspect what's happening after applying codes or input.
        """
        frame = _capture_frame_content(session_ref)
        if frame is None:
            return "No frames available — Dolphin may not be rendering."
        from inspect_ai.model import ContentText

        return [ContentText(text="Screenshot captured."), frame]

    return execute


@tool
def apply_gecko_code(
    session_ref: SessionRef,
    iso_path: Path,
    savestate_path: Path,
    gdb_port: int | None = None,
) -> Tool:
    """Build a tool that reboots Dolphin with a Gecko code applied."""

    async def execute(gecko_text: str) -> list[Any] | str:
        """Reboot Dolphin from the savestate with a Gecko code applied.

        This terminates the current Dolphin session and starts a new one
        with your Gecko code injected. All runtime tools (memory, input,
        position) will work on the new session. Returns a screenshot.

        Args:
            gecko_text: Gecko code text. Use $Name headers and hex-pair lines.
                Example: "$Noclip\\n042967F0 00000001"
        """
        from src.dolphin.gecko import parse_gecko

        codes = parse_gecko(gecko_text)
        if not codes:
            return "Error: no valid Gecko codes found. Use $Name header + hex lines."

        code_summary = ", ".join(f"${c.name} ({len(c.lines)} lines)" for c in codes)
        logger.info("apply_gecko_code", codes=code_summary)

        # Terminate old session + its context manager
        old_session = session_ref.session
        old_cm = getattr(old_session, "_gecko_cm", None)
        try:
            old_session.terminate()
            old_session.cleanup()
        except Exception:
            pass
        if old_cm is not None:
            try:
                old_cm.__exit__(None, None, None)
            except Exception:
                pass

        # Boot new session with gecko codes
        session_cm = DolphinSession.start(
            iso=iso_path,
            savestate=savestate_path,
            gecko_codes=codes,
            pipe_input=True,
            gdb_port=gdb_port,
        )
        new_session = session_cm.__enter__()

        # Store the context manager on the session so the next call can clean it up
        object.__setattr__(new_session, "_gecko_cm", session_cm)

        if not new_session.wait_for_first_frame():
            # Check if process crashed
            rc = new_session.proc.poll()
            if rc is not None:
                return (
                    f"Error: Dolphin crashed (exit code {rc}) after applying Gecko codes — "
                    f"no frames were rendered. The code likely corrupted execution at the "
                    f"patched address. Verify the hook site and instruction encoding."
                )
            return (
                "Error: Dolphin produced no frames within 30s after reboot. "
                "The game may be stuck in an infinite loop or the Gecko code "
                "broke the render path. Try a different approach."
            )

        session_ref.swap(new_session)

        # Wait for game to settle
        time.sleep(2.0)

        frame = _capture_frame_content(session_ref)
        from inspect_ai.model import ContentText

        parts: list[Any] = [
            ContentText(
                text=(f"Gecko codes applied: {code_summary}. Dolphin rebooted from savestate. Game is running.")
            ),
        ]
        if frame is not None:
            parts.append(frame)
        return parts

    return execute


@tool
def save_gecko_code(task_root: Path) -> Tool:
    """Build a tool that saves the final working Gecko code to the task."""

    async def execute(gecko_text: str) -> str:
        """Save the final working Gecko code.

        Call this after you've confirmed the code works.

        Args:
            gecko_text: The complete Gecko code text (with $Name headers).
        """
        from src.dolphin.gecko import parse_gecko

        codes = parse_gecko(gecko_text)
        if not codes:
            return "Error: no valid Gecko codes found."

        code_path = task_root / "gecko_code.txt"
        code_path.write_text(gecko_text)
        logger.info("gecko_code_saved", path=str(code_path), codes=len(codes))
        return f"Saved {len(codes)} Gecko code(s) to {code_path.name}."

    return execute


# Backwards compat alias
save_noclip_code = save_gecko_code
