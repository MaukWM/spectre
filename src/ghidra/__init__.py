"""Ghidra-backed static analysis for spectre."""

from src.ghidra.analyze import (
    CACHE_ROOT,
    cache_dir_for_sha1,
    run_analysis,
    sha1_of,
)
from src.ghidra.cache import (
    callees_of,
    callers_of,
    find_functions,
    load_entry_points,
    load_function_index,
    read_decompiled,
    resolve_function,
    search_strings,
)
from src.ghidra.dol import extract_dol
from src.ghidra.iso import (
    IsoFile,
    IsoHeader,
    extract_iso_file,
    is_executable_candidate,
    list_iso_files,
    patch_elf_machine_ppc,
    read_header,
)
from src.ghidra.notes import NotesStore

__all__ = [
    "CACHE_ROOT",
    "IsoFile",
    "IsoHeader",
    "NotesStore",
    "cache_dir_for_sha1",
    "callees_of",
    "callers_of",
    "extract_dol",
    "extract_iso_file",
    "find_functions",
    "is_executable_candidate",
    "list_iso_files",
    "load_entry_points",
    "load_function_index",
    "patch_elf_machine_ppc",
    "read_decompiled",
    "read_header",
    "resolve_function",
    "run_analysis",
    "search_strings",
    "sha1_of",
]
