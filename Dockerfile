FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# --- System dependencies ------------------------------------------------- #
# Dolphin 2603a from the ubuntuhandbook PPA (matches nix dev environment).
# Savestates are version-pinned, so the container MUST use the same build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      software-properties-common gpg-agent \
    && add-apt-repository -y ppa:ubuntuhandbook1/dolphin-emu \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      dolphin-emu \
      xvfb \
      xauth \
      xdotool \
      ffmpeg \
      libgl1-mesa-dri \
      mesa-utils \
      python3.13 \
      python3.13-venv \
      python3.13-dev \
      ca-certificates \
      curl \
      unzip \
    && rm -rf /var/lib/apt/lists/*

# --- JDK 21 (Adoptium — Ghidra 12.x requires JDK 21+) ------------------ #
RUN curl -fsSL "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse?project=jdk" \
      -o /tmp/jdk.tar.gz \
    && mkdir -p /opt/jdk \
    && tar xzf /tmp/jdk.tar.gz -C /opt/jdk --strip-components=1 \
    && rm /tmp/jdk.tar.gz

ENV JAVA_HOME=/opt/jdk
ENV PATH="/opt/jdk/bin:$PATH"

# --- Ghidra (pinned to 12.0.4 for GameCubeLoader compatibility) --------- #
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip
RUN curl -fsSL "$GHIDRA_URL" -o /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_* /opt/ghidra \
    && rm /tmp/ghidra.zip

# GameCubeLoader extension (DOL/REL support)
ARG GCL_URL=https://github.com/Cuyler36/Ghidra-GameCube-Loader/releases/download/1.3.0/GameCubeLoader-1.3.0-c61f08f-Ghidra_12.0.zip
RUN curl -fsSL "$GCL_URL" -o /tmp/gcl.zip \
    && unzip -q /tmp/gcl.zip -d /opt/ghidra/Ghidra/Extensions \
    && rm /tmp/gcl.zip

ENV DAYWATER_GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Pre-compile only the SLEIGH specs we need: PowerPC (stock) + Gekko/Broadway (GameCubeLoader).
# `sleigh -a` on all Processors takes 10+ minutes for architectures we never use.
RUN /opt/ghidra/support/sleigh -a /opt/ghidra/Ghidra/Processors/PowerPC \
    && /opt/ghidra/support/sleigh \
       /opt/ghidra/Ghidra/Extensions/GameCubeLoader/data/languages/ppc_gekko_broadway.slaspec \
       /opt/ghidra/Ghidra/Extensions/GameCubeLoader/data/languages/ppc_gekko_broadway.sla \
    && chmod -R a+rX /opt/ghidra

# Dolphin + other game binaries live in /usr/games on Debian/Ubuntu
ENV PATH="/usr/games:$PATH"

# --- Runtime user & directories ----------------------------------------- #
# Create dirs and switch to UID 1000 BEFORE installing anything so all
# files are owned correctly without a slow recursive chown.
RUN mkdir -p /data/roms /app/cache /app/logs /app/sessions \
    && chown -R 1000:1000 /app /data

USER 1000

# --- Python dependencies ------------------------------------------------ #
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_PYTHON=python3.13

WORKDIR /app
COPY --chown=1000:1000 pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# --- Application code --------------------------------------------------- #
COPY --chown=1000:1000 src/ src/
COPY --chown=1000:1000 samples/ samples/
COPY --chown=1000:1000 cheats/ cheats/

# --- Runtime config ------------------------------------------------------ #
# Ghidra JVM memory (16 GB server, leave room for Dolphin)
ENV _JAVA_OPTIONS="-Xmx4g"

EXPOSE 7860 7575

# Install gosu for clean privilege drop in entrypoint.
USER root
RUN apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/*

# Entrypoint runs as root to fix bind-mount permissions, then drops to UID 1000.
# Fresh `docker compose up` creates host dirs as root; this makes them writable.
COPY <<'EOF' /app/entrypoint.sh
#!/bin/sh
chown -R 1000:1000 /app/sessions /app/cache /app/logs 2>/dev/null || true
exec gosu 1000:1000 uv run "$@"
EOF
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["daywater-web"]
