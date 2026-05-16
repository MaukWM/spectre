"""Agent tools for runtime Dolphin interaction (memory reads, input, scanning).

These tools wrap a live DolphinSession and are used by tasks that need runtime
access (position discovery, noclip). Each tool is a closure capturing the
session reference.
"""

from __future__ import annotations

import time
from pathlib import Path

from inspect_ai.tool import Tool, tool

from src.dolphin.input import InputSequence, PRESET_NAMES
from src.dolphin.memory import scan_floats_in_range
from src.dolphin.session import DolphinSession
from src.findings import FindingsStore


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
                session.pid, gc_start, gc_end,
                min_abs=min_abs, max_abs=max_abs,
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
            lines.append(
                f"  0x{addr:08X}: {old_v:+.4f} -> {new_v:+.4f} (delta={delta:.4f})"
            )
        if len(changed) > 50:
            lines.append(f"  ... and {len(changed) - 50} more")
        return "\n".join(lines)

    return execute


# ── Input tool ────────────────────────────────────────────────────────── #


@tool
def send_input(session: DolphinSession) -> Tool:
    """Build a controller input tool bound to a DolphinSession."""

    async def execute(action: str, duration: float = 3.0) -> str:
        """Send controller input to the running game.

        Blocks for the duration of the input sequence. Use this to move the
        player character and observe position changes in memory.

        Args:
            action: Input preset name. One of: stand_still, walk_forward,
                walk_backward, strafe_left, strafe_right, jump,
                walk_forward_and_jump, look_up, look_down.
            duration: How long to hold the input in seconds (default: 3.0).
                Keep this short (2-5s) for position testing.
        """
        if duration > 15.0:
            return "Error: duration capped at 15 seconds."
        if duration < 0.5:
            return "Error: duration must be at least 0.5 seconds."

        try:
            seq = InputSequence.from_preset(action, duration)
        except ValueError as e:
            return str(e)

        try:
            session.play_sequence(seq)
        except Exception as e:
            return f"Error sending input: {e}"

        return f"Played '{action}' for {duration:.1f}s."

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
def save_savestate_finding(savestate_root: Path) -> Tool:
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
