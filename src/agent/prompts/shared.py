"""Shared prompt blocks reused across task types."""

TOOLS_STATIC_ANALYSIS = """\
### Static analysis (free, call as much as you want)

- `entry_points()` — list the binary's entry points. **Always start \
  here.** This is where the program begins executing.
- `find_function(pattern, limit=40)` — regex over function names \
  (your renames included). Ghidra strips symbols by default so most \
  names look like `FUN_80123456`; this is most useful after you've \
  renamed functions.
- `find_string(pattern, limit=25)` — regex over string literals in the \
  binary. For each match, returns the string + the functions that \
  reference it. **Hugely effective for finding code paths**: e.g. \
  search for `hud`, `draw`, `health`, debug-print fragments, etc., \
  and you'll often land directly on the relevant function.
- `decompile(addr_or_name)` — C-like pseudocode for one function. \
  Header shows the current name + your note (if any) + a compact \
  callees/callers summary. Body has your renames substituted (so \
  `render_loop()` instead of `FUN_80123456()` if you renamed it). \
  Capped near 16 KB.
- `callees(addr_or_name)` — functions called by this one. Walk *outward*.
- `callers(addr_or_name)` — functions that call this one (xrefs to entry). \
  Walk *inward*."""

TOOLS_BINARY_DISCOVERY = """\
### Binary selection + multi-binary discovery (free)

The task description includes an **inventory** of every executable \
on the disc, each pre-analyzed under its SHA-1. No binary is \
pre-selected; you **must** call `switch_binary(<sha1>)` once before \
any static-analysis tool will return data. You can flip between \
inventoried binaries freely.

- `switch_binary(sha1)` — point the read tools at one of the \
  inventoried binaries (or any binary you later `analyze_binary`). \
  Static-analysis tools (`entry_points`, `find_function`, …) refuse \
  to run until you've called this once.
- `list_iso_contents()` — full FST listing of the disc image, \
  including non-executable assets. The inventory is already a \
  filtered view; reach for this only if you need to see other files \
  (audio, movies, config) or hunt for binaries the survey missed.
- `extract_iso(path_in_iso)` — copy a file out of the ISO to local \
  disk. Returns its SHA-1 + on-disk path. Use when you spot a \
  candidate in `list_iso_contents` that isn't in the inventory.
- `analyze_binary(path)` — run Ghidra on a freshly-extracted file. \
  Cached by SHA-1, so re-analysis is free. **After this call, the \
  read tools target the newly-analyzed binary** until you \
  `switch_binary` again."""

TOOLS_ANNOTATION = """\
### Persistent annotation (free)

- `rename_function(addr_or_name, new_name)` — rename a function. The \
  new name applies to every future tool output, including substitutions \
  inside other functions' decompiled bodies. **Use liberally** — \
  rename anything you've figured out, so future calls read like real \
  code instead of `FUN_xxxxxxxx()` soup.
- `add_note(addr_or_name, text)` — attach a free-text note to a \
  function. Appears in every future `decompile` header. Use for \
  hypotheses, "ruled out because X", "called from main game loop", etc."""

TOOLS_FINDINGS = """\
### Project knowledge base (free, persists across tasks)

- `save_finding(kind, label, detail, address="")` — save a structured \
  discovery. Use `kind="address"` for memory addresses (player position, \
  health pointer), `kind="function"` for function purposes, \
  `kind="note"` for general observations. Upserts by address.
- `list_findings()` — list all structured findings for this game."""

TOOLS_RESEARCH = """\
### Research journal (free, persists across tasks)

- `list_research()` — read the research INDEX.md + list of available \
  docs. **Call this at the start of your run** to see what prior tasks \
  have documented — it may save you significant RE effort.
- `read_research(filename)` — read a specific research document.
- `write_research(filename, content)` — write or update a research \
  document. Use this to document game systems, code structure, function \
  maps, and anything that helps future tasks. Write like a researcher: \
  include addresses, function names, reasoning, and what's confirmed \
  vs hypothetical. You own the INDEX.md — update it when you add docs."""

WORKFLOW_TOP_DOWN = """\
## Suggested workflow — TOP-DOWN, NOT BOTTOM-UP

Treat this like real RE work. Build up a mental model incrementally \
from the program's true entry point down. Resist the urge to grep for \
the answer; map the structure first.

0. **Pick a binary from the inventory.** No binary is pre-selected. \
   Look at the inventory table in the task description and call \
   `switch_binary(<sha1>)` on the one most likely to hold the game \
   logic. Big function count + sensible name = good candidate. Tiny \
   DOL means it's a REL-based game; the real code lives in a `.rel` \
   on the disc. If you pick wrong, just `switch_binary` again later.

1. **Start at `entry_points()`.** The **marked entry** is the *true* \
   program entry — that's your top of the tree. The **orphan roots** \
   are NOT the entry; they're isolated functions reached via vtable / \
   interrupt / dead code. Use orphans only as a fallback when top-down \
   walking gets stuck — do not start from them.

2. **Walk down from the marked entry** for 4–8 decompiles BEFORE you \
   touch `find_string`. The goal: build a top-down map. Use \
   `callees(addr)` to step *down* from a node. Rename + `add_note` \
   aggressively so the tree stays readable as you descend.

3. **THEN use `find_string`** to **confirm** you're in the right \
   region of the map, not to discover the region from scratch. \
   Cross-check every string-xref against your top-down map: if a hit \
   is in a function that isn't reachable from your path (use `callers` \
   to verify), it's noise — skip it.

When you reach a hypothesis worth investigating, leave a brief note \
on the relevant function with `add_note` so your reasoning survives \
across turns. Same for `rename_function` — rename things you've \
figured out."""

SUBMISSION_DOCUMENT = """\
Before submitting your final answer, **document what you learned**:

1. **Save structured findings** via `save_finding` — every function \
   you identified (kind="function"), memory addresses (kind="address"), \
   and key observations (kind="note").
2. **Write a research doc** via `write_research` — a short document \
   summarizing your analysis: what you explored, what the call graph \
   looks like, what you tried and why it worked or didn't, and what \
   questions remain. Then update INDEX.md. \
   Think of this as a handoff note to the next researcher.

This ensures future tasks on this game can build on your work \
instead of re-discovering the same things."""

TOOLS_RUNTIME = """\
### Runtime memory tools (live Dolphin session)

- `read_memory(address, format="f32")` — read a value from GameCube RAM. \
  Formats: "f32" (float), "u32" (unsigned int), "u8" (byte). Address is hex.
- `read_memory_batch(addresses, format="f32")` — read multiple addresses \
  at once. Pass comma-separated hex addresses.
- `scan_memory(start, end, min_abs, max_abs)` — bulk-scan a GC address range \
  for plausible float values. Returns addresses and values. Default range is \
  full MEM1 (0x80000000–0x81800000). Takes several seconds for large ranges.
- `scan_memory_diff(start, end, min_delta, max_delta)` — differential scan. \
  Call once to capture baseline, send input, call again to see what changed. \
  Filters by delta range to find position data (not timers or frame counters).
- `send_input(action, duration)` — send controller input. Actions: \
  stand_still, walk_forward, walk_backward, strafe_left, strafe_right, \
  jump, walk_forward_and_jump, look_up, look_down. Blocks for duration.
- `sample_position(x_addr, y_addr, z_addr, duration, interval)` — poll \
  three addresses over time and return a trajectory table with displacement."""

TOOLS_SAVESTATE_FINDINGS = """\
### Savestate findings (runtime-specific, scoped to this savestate)

- `save_savestate_finding(kind, label, detail, address="")` — save a \
  runtime discovery. Use kind="address" for RAM addresses (player_x, \
  player_y, player_z). These are specific to this savestate's memory layout.
- `list_savestate_findings()` — list all findings saved for this savestate."""

# Convenience: all shared tool docs concatenated
TOOLS_ALL_STATIC = "\n\n".join([
    TOOLS_STATIC_ANALYSIS,
    TOOLS_BINARY_DISCOVERY,
    TOOLS_ANNOTATION,
    TOOLS_FINDINGS,
    TOOLS_RESEARCH,
])
