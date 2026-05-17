"""Headless Ghidra runner via PyGhidra.

PyGhidra lets us drive Ghidra's Java API directly from Python 3, no
subprocess / postScript dance. We import the DOL, run auto-analysis,
walk every function, decompile each, and write a JSON index plus a
per-function pseudocode file.

The Ghidra install path must be in `DAYWATER_GHIDRA_HOME`. PyGhidra
discovers it via the standard `GHIDRA_INSTALL_DIR` env var, so we
mirror it into the subprocess env before `pyghidra.start()`.

GameCubeLoader (community extension; ships in the user's Ghidra
install) handles DOL section mapping automatically. Its only headless
gotcha is an interactive "load a symbol map?" prompt; we satisfy it by
dropping an empty `<dolname>.map` next to the DOL.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from src.logging import logger

# Content-addressed cache root. One subdirectory per binary SHA-1; shared
# across samples and across runs. Gitignored.
CACHE_ROOT = Path(__file__).resolve().parents[2] / "cache" / "binaries"


def cache_dir_for_sha1(sha1: str) -> Path:
    """Return the cache directory for a given binary SHA-1."""
    return CACHE_ROOT / sha1


def sha1_of(path: Path) -> str:
    """Public SHA-1 helper; identical to the value used to key the cache."""
    return _sha1(path)


@dataclass(frozen=True)
class AnalysisResult:
    cache_dir: Path
    project_dir: Path
    sha1: str
    function_count: int


def _resolve_ghidra_home() -> Path:
    raw = os.environ.get("DAYWATER_GHIDRA_HOME")
    if not raw:
        raise RuntimeError("DAYWATER_GHIDRA_HOME not set (path to a Ghidra install)")
    home = Path(raw).expanduser().resolve()
    if not (home / "support" / "analyzeHeadless").exists():
        raise FileNotFoundError(f"not a Ghidra install root: {home}")
    return home


def _sha1(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_elf(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(4) == b"\x7fELF"


def _ensure_empty_map(binary_path: Path) -> None:
    """Create an empty `<binary>.map` if missing — only relevant for DOLs.

    GameCubeLoader prompts for a symbol map at load time when its auto
    discovery finds nothing. An empty map satisfies "something was found"
    and skips the GUI dialog (which fatally fails in headless mode). ELFs
    use Ghidra's stock ElfLoader and don't need this workaround.
    """
    if _is_elf(binary_path):
        return
    map_path = binary_path.with_suffix(".map")
    if not map_path.exists():
        map_path.write_text("")


def run_analysis(
    binary_path: Path,
    cache_dir: Path | None = None,
    *,
    project_name: str = "daywater",
    force: bool = False,
    on_detail: object | None = None,
) -> AnalysisResult:
    """Analyze `binary_path` (ELF or DOL) and dump a content-addressed cache.

    If `cache_dir` is None, derives the cache path from the binary's SHA-1
    via `cache_dir_for_sha1`. The same binary across samples / runs hits
    the same cache and skips re-analysis.
    """
    home = _resolve_ghidra_home()
    os.environ["GHIDRA_INSTALL_DIR"] = str(home)

    binary_path = binary_path.resolve()
    _ensure_empty_map(binary_path)
    binary_sha1 = _sha1(binary_path)

    if cache_dir is None:
        cache_dir = cache_dir_for_sha1(binary_sha1)
    cache_dir = cache_dir.resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    decomp_dir = cache_dir / "decompiled"
    decomp_dir.mkdir(exist_ok=True)

    sentinel = cache_dir / ".binary_sha1"
    if not force and sentinel.exists() and sentinel.read_text().strip() == binary_sha1:
        existing = list(decomp_dir.glob("*.txt"))
        logger.info("analysis_cache_hit", sha1=binary_sha1, functions=len(existing))
        return AnalysisResult(
            cache_dir=cache_dir,
            project_dir=cache_dir / "_project",
            sha1=binary_sha1,
            function_count=len(existing),
        )

    project_dir = cache_dir / "_project"
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir(parents=True)

    logger.info("analysis_start", binary=str(binary_path), cache=str(cache_dir))
    n = _run_pyghidra(
        binary_path,
        project_dir,
        project_name,
        decomp_dir,
        functions_json=cache_dir / "functions.json",
        callgraph_json=cache_dir / "callgraph.json",
        strings_json=cache_dir / "strings.json",
        entry_points_json=cache_dir / "entry_points.json",
        on_detail=on_detail,
    )
    sentinel.write_text(binary_sha1)
    meta = {
        "sha1": binary_sha1,
        "source_path": str(binary_path),
        "functions": n,
    }
    (cache_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    logger.info("analysis_done", sha1=binary_sha1, functions=n)
    return AnalysisResult(
        cache_dir=cache_dir,
        project_dir=project_dir,
        sha1=binary_sha1,
        function_count=n,
    )


def _run_pyghidra(
    binary_path: Path,
    project_dir: Path,
    project_name: str,
    decomp_dir: Path,
    *,
    functions_json: Path,
    callgraph_json: Path,
    strings_json: Path,
    entry_points_json: Path,
    on_detail: object | None = None,
) -> int:
    def _detail(msg: str) -> None:
        if callable(on_detail):
            on_detail(msg)

    # Lazy import — pyghidra.start() spins up the JVM, slow on first call.
    import pyghidra

    _detail("starting JVM...")
    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    _detail(f"loading {binary_path.name} into Ghidra...")
    with pyghidra.open_program(
        binary_path,
        project_location=str(project_dir),
        project_name=project_name,
        analyze=True,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        lang = str(program.getLanguage().getLanguageDescription().getDescription())
        compiler = str(program.getCompilerSpec().getCompilerSpecDescription().getCompilerSpecName())
        _detail(f"auto-analysis complete — language: {lang}, compiler: {compiler}")

        listing = program.getListing()
        funcs = list(program.getFunctionManager().getFunctions(True))
        total = len(funcs)
        _detail(f"found {total:,} functions — starting decompilation")

        decompiler = DecompInterface()
        decompiler.openProgram(program)
        monitor = ConsoleTaskMonitor()

        entries: list[dict[str, str | int]] = []
        callgraph: dict[str, dict[str, list[dict[str, object]] | list[str]]] = {}

        # Build a quick addr → name map up-front (used to label callees/callers
        # with whatever Ghidra auto-named them at analysis time).
        name_by_addr = {f"{int(f.getEntryPoint().getOffset()):08x}": str(f.getName()) for f in funcs}

        for idx, f in enumerate(funcs):
            # Report progress every 100 functions or for the first and last
            if idx % 100 == 0 or idx == total - 1:
                _detail(f"decompiling {idx + 1:,}/{total:,}: {str(f.getName())}")

            addr = int(f.getEntryPoint().getOffset())
            name = str(f.getName())
            size = int(f.getBody().getNumAddresses())
            addr_hex = f"{addr:08x}"
            entries.append({"addr": addr_hex, "name": name, "size": size})

            callees: list[dict[str, object]] = []
            for callee in f.getCalledFunctions(monitor):
                c_addr = f"{int(callee.getEntryPoint().getOffset()):08x}"
                callees.append({"addr": c_addr, "name": str(callee.getName())})

            callers: list[str] = []
            for caller in f.getCallingFunctions(monitor):
                callers.append(f"{int(caller.getEntryPoint().getOffset()):08x}")

            callgraph[addr_hex] = {"callees": callees, "callers": callers}

            try:
                res = decompiler.decompileFunction(f, 60, monitor)
                if res is not None and res.decompileCompleted():
                    code = str(res.getDecompiledFunction().getC())
                else:
                    msg = res.getErrorMessage() if res is not None else "no result"
                    code = f"// decompile failed: {msg}\n"
            except Exception as exc:  # noqa: BLE001 — keep one bad func from killing the run
                code = f"// decompile exception: {exc}\n"

            (decomp_dir / f"{addr_hex}.txt").write_text(code)

        decompiler.dispose()
        _detail(f"decompilation complete — writing {total:,} functions + call graph")

        functions_json.write_text(json.dumps({"functions": entries}, indent=2))
        callgraph_json.write_text(json.dumps(callgraph, indent=2))

        # Defined strings + xrefs into them. We tag each xref with the
        # containing function (if any) so the agent can jump straight from
        # a string hit to a code site.
        _detail("extracting strings + cross-references...")
        strings_out: list[dict[str, object]] = []
        ref_mgr = program.getReferenceManager()
        fm = program.getFunctionManager()
        for data in listing.getDefinedData(True):
            dt = data.getDataType()
            type_name = str(dt.getName()).lower()
            if "string" not in type_name and "char" not in type_name:
                continue
            try:
                value = data.getValue()
            except Exception:  # noqa: BLE001
                continue
            if not isinstance(value, str) or not value:
                continue
            text = value[:160]
            saddr = int(data.getAddress().getOffset())
            xrefs_to: list[str] = []
            for ref in ref_mgr.getReferencesTo(data.getAddress()):
                from_addr = ref.getFromAddress()
                fn = fm.getFunctionContaining(from_addr)
                if fn is not None:
                    xrefs_to.append(f"{int(fn.getEntryPoint().getOffset()):08x}")
            if not xrefs_to:
                # Skip strings nobody references — noise, lots of them in ELFs.
                continue
            # Dedupe while preserving order.
            seen: set[str] = set()
            uniq = []
            for x in xrefs_to:
                if x not in seen:
                    seen.add(x)
                    uniq.append(x)
            strings_out.append({"addr": f"{saddr:08x}", "text": text, "xrefs": uniq})
        _detail(f"found {len(strings_out):,} referenced strings")
        strings_json.write_text(json.dumps({"strings": strings_out}, indent=2))

        # Entry points = anywhere the loader marked external entry, plus the
        # symbol-table entry if defined.
        _detail("extracting entry points...")
        entry_addrs: list[str] = []
        for ep in program.getSymbolTable().getExternalEntryPointIterator():
            ep_hex = f"{int(ep.getOffset()):08x}"
            entry_addrs.append(ep_hex)
        entry_points_json.write_text(
            json.dumps(
                {
                    "entries": [
                        {"addr": a, "name": name_by_addr.get(a, "<unmapped>")}
                        for a in entry_addrs
                    ],
                },
                indent=2,
            )
        )

        return len(entries)
