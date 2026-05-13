# spectre

Automatically find scene-manipulation Gecko cheats (HUD removal only currently) for GameCube games. Given a ROM, a reference frame, and a HUD mask, the agent iterates Gecko candidates against a Dolphin verifier.


## Prerequisites

| Tool | Purpose | Required for |
|---|---|---|
| [Dolphin Emulator](https://dolphin-emu.org/) | GameCube emulation (`dolphin-emu-nogui` on Linux, `Dolphin.app` on macOS) | Everything |
| Python 3.13+ | Runtime | Everything |
| [uv](https://docs.astral.sh/uv/) | Package manager | Everything |
| [Ghidra](https://ghidra-sre.org/) | Static binary analysis | Cheat discovery (agent needs it to reverse-engineer game binaries) |

## Setup

### Option A: Nix flake (recommended)

The flake provides Dolphin, Ghidra, Python 3.13, and uv in one command:

```bash
cd spectre
nix develop          # drops you into a shell with all tools
uv sync              # install Python deps
uv run pre-commit install
cp .env.example .env # optional — env vars can also be passed via CLI
```

Verify the shell has everything:

```bash
dolphin-emu-nogui --help  # should print usage
python3 --version         # 3.13+
uv --version
```

### Option B: Manual install

Install Dolphin, Python 3.13+, uv, and Ghidra through your system package
manager, then:

```bash
cd spectre
uv sync
uv run pre-commit install
cp .env.example .env
```

**macOS:** `brew install --cask dolphin` places `Dolphin.app` at
`/Applications/Dolphin.app` (the runner auto-detects this).

**Linux:** The runner looks for `dolphin-emu-nogui` (preferred) or
`dolphin-emu` in `$PATH`.

## Game files

The CLI tools require a GameCube ISO (`.iso`, `.nkit.iso`, or `.rvz`) and a
Dolphin savestate (`.s##`) with an in-game scene loaded. The savestate must
be created with the same Dolphin build you'll use to run spectre — save
states are not portable across Dolphin versions. The nix flake pins
Dolphin `2603a`.

### Creating a savestate

1. Open Dolphin GUI. On **Wayland** (Hyprland, Sway, etc.), Dolphin's input
   is completely broken — you must wrap it with gamescope:
   ```bash
   gamescope -w 800 -h 600 -- dolphin-emu /path/to/game.iso
   ```
   On **X11** or **macOS**, launch directly: `dolphin-emu` / `Dolphin.app`.
2. Boot the game ISO
3. Play until you're in-game with the HUD visible on screen
4. Save state to slot 1 (Emulation > Save State > Slot 1, or `Shift+F1`)
5. The savestate lands at `~/.local/share/dolphin-emu/StateSaves/<GAMEID>.s01` (Linux)
   or `~/Library/Application Support/Dolphin/StateSaves/<GAMEID>.s01` (macOS)

## CLI

Two entry points are installed by `uv sync`:

```bash
# boot Dolphin once, dump frames
uv run spectre-probe --iso PATH --savestate PATH [--gecko PATH] --out DIR --run-seconds N

# pixel-diff two frame-dump directories
uv run spectre-diff --a DIR --b DIR [--frames last|all|N,N,...]
```

Flags: `spectre-probe --help`, `spectre-diff --help`.

## Usage

Set `OPENAI_API_KEY` in `.env` or export it, then point spectre at a game:

```bash
uv run inspect eval src/agent/task.py \
  --model openai/gpt-5.5 \
  -T iso=/path/to/game.iso \
  -T savestate=/path/to/GAMEID.s01
```

Any Inspect AI-compatible model works — see `.env.example` for details.

Ghidra is required for the agent to reverse-engineer game binaries. The nix
flake includes Ghidra and auto-sets `SPECTRE_GHIDRA_HOME`. If you're not
using the flake, install Ghidra manually and set:

```bash
export SPECTRE_GHIDRA_HOME=/path/to/ghidra   # must contain support/analyzeHeadless
```

### Viewing results

```bash
uv run inspect view
```

Opens a browser UI at `http://localhost:7575` to browse run logs,
see agent traces, and inspect scores.

## Example: probing a known gecko code

To verify the pipeline works, you can probe a game with and without a gecko
code and diff the results:

```bash
# 1. Baseline capture (no cheat)
uv run spectre-probe \
  --iso /path/to/game.iso \
  --savestate /path/to/GAMEID.s01 \
  --out /tmp/sp_base \
  --run-seconds 10

# 2. Capture with a gecko code applied
uv run spectre-probe \
  --iso /path/to/game.iso \
  --savestate /path/to/GAMEID.s01 \
  --out /tmp/sp_cheat \
  --run-seconds 10 \
  --gecko /path/to/cheat.gecko

# 3. Pixel diff
uv run spectre-diff --a /tmp/sp_base/frames --b /tmp/sp_cheat/frames --frames all
```

HUD regions should show a mean diff >= 5, non-HUD regions near 0.

## Dev

```bash
uv run pre-commit run --all-files
uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```

## Quirks

- Save states are not portable across Dolphin versions; pin one build.
- Linux headless mode uses `dolphin-emu-nogui --platform=headless` (no X needed).
- Docker containers need `docker run --shm-size=2g` (Dolphin MemArena
  exceeds the default 64 MB `/dev/shm`).

