"""One-shot pipeline: extract DOL from ISO (if needed) → run Ghidra → fill cache.

    uv run python scripts/build_analysis.py [sample_name]

Defaults to `nightfire_hud_off`. First run on a ~2 MB ELF takes
~3–5 minutes (Ghidra auto-analysis + per-function decompilation);
re-runs against the same binary hash are no-ops.

Binary preference (driven by `sample.toml`):

1. `binary_env` — env var pointing at a pre-built ELF (decomp project).
   Strongly preferred; covers RELs and the entire address space.
2. Otherwise, `boot.dol` extracted from the ISO. Lower fidelity:
   REL-loaded code is invisible (the agent will see only the bootstrap
   + main DOL text sections).
"""

from __future__ import annotations

import sys
from pathlib import Path

from src.agent.loader import (
    load_sample_config,
    resolve_binary_for_analysis,
    resolve_runtime_paths,
)
from src.ghidra import extract_dol, run_analysis
from src.logging import logger

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


def main() -> int:
    sample_name = sys.argv[1] if len(sys.argv) > 1 else "nightfire_hud_off"
    sample_dir = SAMPLES_DIR / sample_name
    if not sample_dir.is_dir():
        logger.error("sample_not_found", path=str(sample_dir))
        return 2

    cfg = load_sample_config(sample_dir)
    dol_path = sample_dir / "boot.dol"

    # Try the preferred binary first.
    try:
        binary = resolve_binary_for_analysis(cfg, sample_dir)
        logger.info("binary_resolved", path=str(binary))
    except FileNotFoundError:
        # No ELF available; fall back to extracting from the ISO.
        iso, _ = resolve_runtime_paths(cfg)
        logger.info("extracting_dol", iso=str(iso), out=str(dol_path))
        size = extract_dol(iso, dol_path)
        logger.info("dol_extracted", size=size)
        binary = dol_path

    result = run_analysis(binary)
    logger.info(
        "analysis_ready",
        cache=str(result.cache_dir),
        sha1=result.sha1,
        function_count=result.function_count,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
