"""PPC assembly tools for Gecko code authoring.

Wraps keystone-engine to let agents write PowerPC assembly instead of raw hex,
and provides a C2 hook helper that handles save/restore + return-jump automatically.

See spectre_docs/OPEN_QUESTIONS.md §4.7–4.8 and LESSONS_LEARNED.md for motivation.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import structlog
from inspect_ai.tool import Tool, tool

logger = structlog.get_logger()


def _get_ks() -> "keystone.Ks":
    """Lazy-init a PPC32 big-endian Keystone assembler."""
    import keystone

    return keystone.Ks(keystone.KS_ARCH_PPC, keystone.KS_MODE_PPC32 | keystone.KS_MODE_BIG_ENDIAN)


def _normalize_ppc_asm(asm: str) -> str:
    """Strip r/f register prefixes that Keystone PPC doesn't accept.

    Ghidra and standard PPC notation uses ``r3``, ``f1`` etc. but Keystone
    expects bare numeric registers (``3``, ``1``).  We convert ``r0``–``r31``
    and ``f0``–``f31`` to their bare forms, being careful not to mangle
    hex literals, labels, or mnemonics.
    """
    import re

    # Match r0-r31 / f0-f31 that appear as register operands.
    # Negative lookbehind: not preceded by an alphanumeric or underscore
    # (avoids hitting hex digits like 0x1f0 or label names like "start_r3").
    # Negative lookahead: not followed by an alphanumeric (avoids "r31x").
    return re.sub(r"(?<![a-zA-Z0-9_])([rf])(\d{1,2})(?![a-zA-Z0-9_])", r"\2", asm)


def _assemble(asm: str, base_addr: int) -> list[str]:
    """Assemble PPC asm into a list of 8-char uppercase hex words.

    Accepts both Keystone-native syntax (bare register numbers) and standard
    PPC notation with r/f prefixes — prefixes are stripped automatically.

    Raises ValueError on assembly failure.
    """
    asm = _normalize_ppc_asm(asm)
    ks = _get_ks()
    try:
        encoding, _count = ks.asm(asm, addr=base_addr)
    except Exception as exc:
        raise ValueError(f"Assembly failed: {exc}") from exc
    if encoding is None:
        raise ValueError("Assembly produced no output — check syntax")
    # encoding is a list of bytes; group into 4-byte (32-bit) words
    raw = bytes(encoding)
    if len(raw) % 4 != 0:
        raise ValueError(f"Assembly output is {len(raw)} bytes — not aligned to 4-byte PPC words")
    words: list[str] = []
    for i in range(0, len(raw), 4):
        word = int.from_bytes(raw[i : i + 4], "big")
        words.append(f"{word:08X}")
    return words


def _read_insn_from_binary(vaddr: int) -> str | None:
    """Read a 32-bit PPC instruction from the currently-selected binary.

    Uses the Ghidra cache state to find the binary, then reads the raw
    ELF/DOL to get the instruction at the given virtual address.
    Returns an 8-char uppercase hex string, or None if not found.
    """
    from src.agent.state import current_cache_dir

    cache_dir = current_cache_dir()
    if cache_dir is None:
        return None

    meta_path = cache_dir / "meta.json"
    if not meta_path.exists():
        return None

    meta = json.loads(meta_path.read_text())
    source_path = Path(meta.get("source_path", ""))

    # Resolve Docker paths: /app/cache/... → local cache/...
    if not source_path.exists() and str(source_path).startswith("/app/"):
        # Try relative to working directory
        local_path = Path(str(source_path).replace("/app/", "", 1))
        if local_path.exists():
            source_path = local_path

    if not source_path.exists():
        return None

    data = source_path.read_bytes()

    # Detect format: ELF or DOL
    if data[:4] == b"\x7fELF":
        return _read_insn_elf(data, vaddr)
    elif len(data) >= 0x100:
        # DOL format: check if it looks like a DOL header
        return _read_insn_dol(data, vaddr)
    return None


def _read_insn_elf(data: bytes, vaddr: int) -> str | None:
    """Read a 32-bit word from an ELF binary at the given virtual address."""
    ei_class = data[4]
    is_be = data[5] == 2
    endian = ">" if is_be else "<"

    if ei_class != 1:
        return None  # only 32-bit ELF supported

    e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
    e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
    e_phnum = struct.unpack_from(endian + "H", data, 44)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr = struct.unpack_from(endian + "III", data, off)[:3]
        p_filesz = struct.unpack_from(endian + "I", data, off + 16)[0]

        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:  # PT_LOAD
            file_offset = p_offset + (vaddr - p_vaddr)
            if file_offset + 4 <= len(data):
                word = struct.unpack_from(">I", data, file_offset)[0]
                return f"{word:08X}"
    return None


def _read_insn_dol(data: bytes, vaddr: int) -> str | None:
    """Read a 32-bit word from a DOL binary at the given virtual address."""
    # DOL has 7 text sections + 11 data sections
    # Header: offsets at 0x00, addresses at 0x48, sizes at 0x90
    for i in range(18):
        sec_offset = struct.unpack_from(">I", data, i * 4)[0]
        sec_addr = struct.unpack_from(">I", data, 0x48 + i * 4)[0]
        sec_size = struct.unpack_from(">I", data, 0x90 + i * 4)[0]

        if sec_offset == 0 or sec_size == 0:
            continue
        if sec_addr <= vaddr < sec_addr + sec_size:
            file_offset = sec_offset + (vaddr - sec_addr)
            if file_offset + 4 <= len(data):
                word = struct.unpack_from(">I", data, file_offset)[0]
                return f"{word:08X}"
    return None


@tool
def assemble_ppc() -> Tool:
    """Build the assemble_ppc agent tool."""

    async def execute(asm: str, base_addr: int = 0x80000000) -> str:
        """Assemble PowerPC assembly into hex words for Gecko codes.

        Args:
            asm: PPC assembly source. Multiple instructions separated by
                 semicolons or newlines. Both r-prefix (r0, f1) and bare
                 numeric (0, 1) register notation are accepted.
                 Example: "mflr r0; stwu r1, -0x40(r1)"
            base_addr: Address where the code will be placed in memory.
                       Required for correct branch displacement calculation.
                       Default 0x80000000; set to actual target address.

        Returns:
            Space-separated 8-char hex words ready for Gecko 04-write blocks,
            e.g. "7C0802A6 9421FFC0".
        """
        try:
            words = _assemble(asm, base_addr)
        except ValueError as exc:
            return f"Error: {exc}"

        result = " ".join(words)
        logger.info("assemble_ppc", instruction_count=len(words), base_addr=f"0x{base_addr:08X}")
        return result

    return execute


@tool
def make_c2_hook() -> Tool:
    """Build the make_c2_hook agent tool."""

    async def execute(hook_addr: int, asm: str, name: str = "Hook") -> str:
        """Create a complete Gecko C2 hook from PowerPC assembly.

        The C2 codetype replaces the instruction at hook_addr with a branch
        to the Gecko codehandler, which runs your body code, then branches
        to hook_addr+4. The original instruction at hook_addr is automatically
        read from the currently-selected binary and prepended to your body.

        Args:
            hook_addr: The address to hook (e.g. 0x8029918C). Must be in
                       the 0x80000000–0x817FFFFF range (MEM1).
            asm: PPC assembly for the hook body. Write only your custom logic;
                 the original instruction is auto-prepended from the binary.
                 Do NOT include prologue/epilogue or a return branch.
                 Example: "lis r4, 0x4120; stw r4, 8(r1); lfs f1, 8(r1)"
            name: Name for the Gecko code block (default "Hook").

        Returns:
            Complete Gecko code text with $Name header, C2 codetype lines,
            and terminator — ready to pass to apply_gecko_code.
        """
        # Validate hook address is in MEM1
        if not (0x80000000 <= hook_addr <= 0x817FFFFF):
            return f"Error: hook_addr 0x{hook_addr:08X} is outside MEM1 range (0x80000000–0x817FFFFF)"

        # Auto-read the original instruction from the binary
        original_hex = _read_insn_from_binary(hook_addr)
        if original_hex is None:
            return (
                f"Error: could not read the original instruction at 0x{hook_addr:08X} "
                f"from the current binary. Make sure you've called switch_binary() first."
            )

        # Assemble the body
        try:
            words = _assemble(asm, hook_addr)
        except ValueError as exc:
            return f"Error: {exc}"

        if not words:
            return "Error: assembly produced no instructions"

        # Prepend the original instruction so the hooked function still works.
        # Dolphin's C2 codehandler does NOT re-execute the original instruction;
        # it branches to hook_addr+4 after running the body.
        body_words = [original_hex] + list(words)

        # Build C2 block
        # C2 header: C2XXXXXX 0000000N where XXXXXX = addr & 0x01FFFFFF
        # N = number of 8-byte lines in the body, EXCLUDING the terminator.
        masked_addr = hook_addr & 0x01FFFFFF
        # Pad with a nop if odd number of words so body is word-pair aligned.
        if len(body_words) % 2 != 0:
            body_words.append("60000000")  # nop padding

        # N counts only body pairs, not the terminator
        n_pairs = len(body_words) // 2

        # Terminator: 00000000 00000000 (always present, not counted in N)
        body_words.extend(["00000000", "00000000"])

        lines: list[str] = [f"${name}"]
        lines.append(f"C2{masked_addr:06X} {n_pairs:08X}")
        for i in range(0, len(body_words), 2):
            lines.append(f"{body_words[i]} {body_words[i + 1]}")

        result = "\n".join(lines)
        logger.info(
            "make_c2_hook",
            hook_addr=f"0x{hook_addr:08X}",
            original_insn=original_hex,
            body_instructions=len(words),
            gecko_lines=len(lines) - 1,
        )
        return result

    return execute
