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

- `list_research()` — read the auto-generated research index with \
  summaries of all available docs. **Call this at the start of your run** \
  to see what prior tasks have documented — it may save you RE effort.
- `read_research(filename)` — read a specific research document.
- `write_research(filename, content, summary)` — write or update a \
  research document. Use this to document game systems, code structure, \
  function maps, and anything that helps future tasks. Write like a \
  researcher: include addresses, function names, reasoning, and what's \
  confirmed vs hypothetical. **Provide a one-line summary** — it appears \
  in the index shown to future tasks. Do NOT write to INDEX.md (it's \
  auto-generated from summaries)."""

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
2. **Write a research doc** via `write_research(filename, content, summary)` \
   — a document summarizing your analysis: what you explored, what the \
   call graph looks like, what you tried and why it worked or didn't, \
   and what questions remain. Include a concise summary — it appears in \
   the auto-generated index for future tasks.

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
- `sample_position(x_addr, y_addr, z_addr, duration, interval)` — poll \
  three addresses over time and return a trajectory table with displacement.

### Write watchpoint (GDB stub)

- `find_writers(address, duration=3.0)` — set a hardware write watchpoint \
  on a memory address and collect all code locations (PCs) that write to it. \
  Returns a list of PC addresses with hit counts. Use `decompile(pc)` on \
  the results to see the writing code and determine if an address is the \
  authoritative source or a copy.

### Controller input (raw GameCube controller)

- `press_button(button, duration=0.3)` — press and release a button. \
  Buttons: A, B, X, Y, Z, START, L, R, D_UP, D_DOWN, D_LEFT, D_RIGHT.
- `set_stick(stick, x, y, duration=3.0)` — hold an analog stick at a \
  position (0.0–1.0, 0.5=neutral), then return to neutral. \
  stick="MAIN" for left stick, stick="C" for C-stick. \
  MAIN: x=0.0 full left, x=1.0 full right, y=0.0 full forward, y=1.0 full backward. \
  C-stick: same mapping (typically camera control).
- `wait(duration=2.0)` — let the game run with no input for a duration. \
  Useful to let physics settle or observe values at rest."""

TOOLS_PPC_ASM = """\
### PPC assembly tools (available with Gecko injection)

- `assemble_ppc(asm, base_addr=0x80000000)` — assemble PowerPC instructions \
  into hex words. Write standard PPC syntax (`mflr r0; stwu r1, -0x40(r1)`) \
  and get back space-separated hex words (`7C0802A6 9421FFC0`) ready for \
  Gecko 04-write blocks. Both `r`-prefix (`r3`, `f1`) and bare numeric \
  register notation are accepted. Set `base_addr` to the actual target \
  address for correct branch displacement calculation. **Always use this \
  instead of hand-computing PPC hex** — branch displacement math is the \
  #1 source of silent Gecko bugs.
- `make_c2_hook(hook_addr, asm, name="Hook")` — create a complete Gecko C2 \
  hook. Write ONLY your custom logic in `asm` (no prologue/epilogue, no \
  return branch). The tool automatically reads the original instruction at \
  hook_addr from the current binary and prepends it to your body — this is \
  required because Dolphin's C2 handler skips the hooked instruction. \
  Make sure you've called `switch_binary()` before using this tool. \
  Returns a complete `$Name` Gecko block ready for `apply_gecko_code`. \
  **Use C2 hooks for any patch more complex than a simple NOP/BLR.**"""

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
