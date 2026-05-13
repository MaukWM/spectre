{
  description = "spectre — automatic Gecko cheat discovery for GameCube games";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            # Emulator
            pkgs.dolphin-emu          # dolphin-emu, dolphin-emu-nogui, dolphin-tool

            # Wayland input fix — gamescope wraps Dolphin with proper input passthrough
            pkgs.gamescope

            # Python
            pkgs.python313
            pkgs.uv

            # Frame extraction from AVI dumps
            pkgs.ffmpeg

            # Static analysis
            pkgs.ghidra

            # Useful for development
            pkgs.git
          ];

          # Native Python extensions (numpy, pillow) need system libs
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
            pkgs.stdenv.cc.cc.lib    # libstdc++
            pkgs.zlib                # libz
          ];

          SPECTRE_GHIDRA_HOME = "${pkgs.ghidra}/lib/ghidra";

          shellHook = ''
            echo "spectre dev shell"
            echo "  dolphin-emu-nogui: $(which dolphin-emu-nogui)"
            echo "  python:            $(python3 --version)"
            echo "  uv:                $(uv --version)"
            echo "  ffmpeg:            $(ffmpeg -version 2>&1 | head -1)"
            echo "  ghidra:            $SPECTRE_GHIDRA_HOME"
            echo ""
            echo "Next steps:"
            echo "  cd spectre && uv sync"
            echo "  Place ISO at roms/nightfire.iso"
            echo "  Create savestate at roms/GO7E69.s01"
            echo "  uv run spectre-probe --iso roms/nightfire.iso --savestate roms/GO7E69.s01 --out /tmp/sp_base --run-seconds 10"
          '';
        };
      });
}
