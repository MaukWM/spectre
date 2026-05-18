"""Strategy blocks for find_code_patch tasks (HUD removal, noclip, etc.)."""

GECKO_FORMAT = """\
## Gecko code format

Gecko codes are written as `TTXXXXXX YYYYYYYY` where TT is the code type:
- **04** = 32-bit write: `04XXXXXX YYYYYYYY` writes word to 0x80XXXXXX
- **02** = 16-bit write: `02XXXXXX 0000YYYY` writes halfword to 0x80XXXXXX
- **00** = 8-bit write: `00XXXXXX 000000YY` writes byte to 0x80XXXXXX

The address in the code is the LOW 24 bits (strip the `80` prefix). \
For example, to write 0x01 to 0x8029F7F1: `0029F7F1 00000001`.

Submit format:
```
$DescriptiveName
<8-hex-digits-address> <8-hex-digits-value>
```

You can submit multiple `$Name` blocks in one call.

**Do not use the Gecko `C0000000` opcode** (execute arbitrary injected \
PowerPC code without a hook site). For complex patches that need more \
than a simple NOP/BLR/value-write, use the `make_c2_hook` tool which \
generates correct C2 (hook-at-address) blocks with proper save/restore \
and return handling. For simple patches, stick to 04/02/00 writes."""

PATCHING_PATTERNS = """\
## Standard PowerPC patch patterns

- **NOP a call site**: replace the `bl <target>` at the call site with \
  `60000000` (`nop`). The function is never invoked. Address = the \
  call instruction itself. Local, surgical.
- **BLR a function**: replace the *first instruction* of the target \
  function with `4E800020` (`blr` — branch-to-link-register / return). \
  The function returns immediately. Address = the function's entry point.

Both leave surrounding code untouched. Prefer them over forward branches \
(`48000NNN` = `b +NNN`) which skip arbitrary byte counts and break if \
the compiler rearranges anything.

For patches beyond simple NOP/BLR — such as injecting custom logic, \
modifying a value in-flight, or hooking a function — use the \
`make_c2_hook` tool. It automatically reads the original instruction from \
the binary and handles the C2 encoding. **Never hand-compute PowerPC \
hex.** Use `assemble_ppc` to convert mnemonics to hex, and `make_c2_hook` \
for any multi-instruction patch."""

ROBUSTNESS = """\
## Robustness requirement — MANDATORY

Your Gecko code MUST be savestate-agnostic. It must work from ANY savestate \
of the same game, not just the one you're testing with. This means:

- **Patch CODE addresses only** — code segment addresses (0x800xxxxx–0x8029xxxx \
  typically) are stable across all boots and savestates.
- **NEVER write to heap/object addresses** in Gecko codes. Heap addresses \
  (0x80Axxxxx, 0x80Bxxxxx, 0x817xxxxx) differ per boot and per savestate.
- **Link every patch to decompiled code** — before writing a Gecko code, \
  `decompile()` the target address and verify it's the function you intend \
  to patch. Document which function and what the patch does.
- **Verify via code, not via side effects** — after applying a code, \
  read the patched address to confirm the instruction was replaced."""

STRATEGY_VISUAL = """\
## Strategy — visual code patch (HUD removal)

For HUD work specifically:

- The goal of your top-down walk is a map shaped like \
  `entry → boot/init → main_loop → per_frame_dispatcher → render → \
  HUD_dispatcher → individual_HUD_components`.
- When using `find_string`, search for `hud`, `health`, `ammo`, \
  `draw`, `render`, `gui`, `overlay`.
- **Pick a candidate patch site** from the render dispatcher's \
  *direct callees*, not a deep leaf. The closer to the dispatcher, \
  the more HUD elements you kill in one patch.
- **Don't tunnel-vision a region.** If 2 consecutive test calls \
  in the same address neighbourhood show no effect, you're in the wrong \
  area. Walk further up/down the call graph.
- **Don't BLR a function just because `find_string` hit it.** Verify \
  it's on the per-frame render path via `callers` first.
- **Don't submit untested gecko.** Every code you submit MUST have \
  been tested at least once in this session.

### What the feedback means

- `hud_mean`: mean per-channel pixel difference vs reference inside \
  the masked HUD region. **Bigger is better** (HUD pixels changed).
- `preserve_mean`: mean per-channel diff outside the mask. \
  **Smaller is better** (scene preserved).
- `verdict`: PASS (both criteria met) / FAIL (one or both missed).
- A screenshot showing what Dolphin rendered with your code applied.

Look at the screenshot, not just the numbers. A black screen scores \
"HUD removed" perfectly but means your patch broke rendering entirely."""

STRATEGY_INTERACTIVE = """\
## Strategy — interactive code patch (noclip/behavioral)

### Step 1: Read prior knowledge

Call `list_research()` and `list_findings()` to see what earlier tasks \
discovered. Research docs may describe the exact mechanism you need.

### Step 2: Look for a built-in debug/noclip mode FIRST

Many GameCube games ship with debug fly/noclip/ghost modes that are just \
disabled via a flag. This is the easiest and most robust path — a single \
byte write to a global data address. Before trying anything else:

1. Use `find_string()` to search for debug-related strings: `debug`, \
   `fly`, `noclip`, `ghost`, `free`, `cam`, `cheat`, `god`. These often \
   appear in debug menus or print statements near the flag check.
2. Check the movement/player-update function for branches that test a \
   global flag (a load from a fixed data-segment address like \
   `0x8029xxxx` or `0x802Axxxx`, compared to zero). Decompile the \
   movement function and look for early `if (DAT_802xxxxx != 0)` guards \
   that switch between normal and debug movement modes.
3. If you find a candidate flag, test it immediately with a Gecko code \
   that sets it to 1 (or the expected value).

Only proceed to Step 3 if no built-in debug mode is found.

### Step 3: Synthesize a Gecko code (if no debug mode)

If there's no built-in debug flag, create a Gecko code targeting \
GLOBAL/CODE addresses. Good targets:
- **NOP a collision call**: use `assemble_ppc("nop")` → `60000000`, \
  then write a 04-line to skip collision.
- **NOP a gravity/physics call**: skip gravity so the player floats.
- **Patch a branch**: change a conditional branch to skip collision/physics.
- **Force a movement state**: patch the state machine to always enter \
  the fly/noclip state.
- **Inject custom logic**: use `make_c2_hook(hook_addr, asm)` for complex \
  patches that need more than a single instruction change.

**Always use `assemble_ppc` for instruction hex** — never hand-compute it.

### Step 4: Test the code — MANDATORY

After applying the code, verify it works:
1. Let the game settle after reboot.
2. Read position/relevant addresses to confirm they're valid.
3. Verify the patched memory has the expected value.
4. Test the behavior (movement, interaction, etc.).

### Step 5: Iterate if needed

If the code doesn't produce the expected behavior:
- Verify the address is correct and the value was written.
- Try a different approach (NOP collision vs setting a flag, etc.).
- Use `decompile()` to find the exact branch or call to patch.

### Step 6: Save and document

Only after confirming the code works:
1. Save the working Gecko code.
2. Document what you learned via `save_finding` and `write_research`.
3. Submit a summary of the code, what it patches, and how you verified it."""
