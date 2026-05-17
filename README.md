# Daywater

AI-Driven GameCube reverse engineering platform.

## Quick Start (Docker)

```bash
cd daywater
docker compose up --build -d
```

Open `http://localhost:7860`. On first launch, a setup wizard walks you through:

1. **API key + model** — configure your LLM backend (default: `openai/gpt-5.5`)
2. **Ghidra initialization** — warms the JVM and verifies the analysis engine

After setup: upload an ISO, upload a savestate, create a task, run the agent.

- **Web UI:** `http://localhost:7860`
- **Inspect AI viewer:** `http://localhost:7575` — detailed agent traces

**Requirements:** Docker, 8 GB+ RAM (16 GB recommended), `--shm-size=2g` (set in compose).

## What It Does

Daywater has a **unified task system** with three goal types:

- **Find code patch** — write Gecko cheat codes (HUD removal, noclip, etc.)
- **Find RAM address** — locate memory addresses (health, position, ammo)
- **Static research** — explore and document game internals

Each task is independently configured with **capabilities** (static RE, Gecko injection, RAM poke, input injection, frame capture, pixel diff), evaluation method, budget, and input-mutation hints. Presets are available for common workflows.

### Key Features

- **ISO survey** — uploads an ISO, extracts all executables, runs Ghidra auto-analysis with live progress streaming
- **Disc contents browser** — tree view of the full ISO filesystem with file sizes and analysis badges
- **Knowledge base** — findings, function renames, notes, and research docs persist across tasks
- **Per-task knowledge tracking** — delete a task and its findings/renames/docs are cleaned up
- **Controller mapping** — describe what each GC input does so the agent knows the controls
- **Savestate management** — upload multiple savestates, render screenshots, track findings per savestate
- **Mask painter** — paint HUD regions for pixel-diff evaluation (specifically for HUD disabling tasks)

## Architecture

```
src/
  agent/         # Inspect AI task, prompts, tools, scorers, job spec system
  dolphin/       # Dolphin runner, frame capture, memory tools, Gecko injection
  ghidra/        # PyGhidra analysis, ISO parsing, binary cache
  web/           # FastAPI app, frontend, SSE events, survey runner
```

The agent runs via [Inspect AI](https://inspect.ai). Ghidra runs in-process via [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra) (no subprocess). Dolphin runs headless via `dolphin-emu-nogui`.

## Local Dev

### Nix flake (recommended)

```bash
nix develop          # shell with Dolphin, Ghidra, Python 3.13, uv
uv sync
```

### Manual

Install Dolphin, Python 3.13+, uv, and Ghidra, then:

```bash
uv sync
export DAYWATER_GHIDRA_HOME=/path/to/ghidra
```

### Savestates

Savestates must be created with **[Dolphin 2603a](https://dolphin-emu.org/download/release/2603a/)** (the build in the container and nix flake). They are not portable across Dolphin versions.

1. Boot the game in Dolphin GUI
2. Play to an in-game scene
3. Save state (Shift+F1)
4. Upload via the web UI

On Wayland, wrap Dolphin with gamescope: `gamescope -w 800 -h 600 -- dolphin-emu /path/to/game.iso`

## Dev Commands

```bash
uv run pre-commit run --all-files
uv run pytest
```

## Docker Notes

- `init: true` in compose for zombie reaping (Dolphin child processes)
- `cap_add: SYS_PTRACE` for memory debugging tools
- `shm_size: 2g` required (Dolphin MemArena exceeds default 64 MB `/dev/shm`)
- Ghidra SLEIGH specs are pre-compiled in the image including GameCubeLoader's Gekko/Broadway language
- The entrypoint fixes bind-mount permissions automatically on fresh deploys

## AI Development Disclosure

Yes, AI was heavily employed in the creation of this project. Shoutouts to claude for figuring out how to get ghidra and dolphin work in docker containers.