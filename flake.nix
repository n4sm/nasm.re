{
  description = "Astro/Fuwari website";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;

      mkPkgs = system: import nixpkgs { inherit system; };

      # pnpm 9 is end-of-life and is blocked by Nixpkgs due to known CVEs.
      # Require a pnpm 10 release containing the current security fixes.
      mkPnpm = pkgs:
        let
          minimumVersion = "10.34.5";
          candidate = pkgs.pnpm_10;
        in
        if pkgs.lib.versionAtLeast candidate.version minimumVersion then
          candidate
        else
          throw ''
            This flake requires pnpm >= ${minimumVersion}, but the pinned
            nixpkgs provides pnpm ${candidate.version}.

            Update the lock file with:

              nix flake update nixpkgs
          '';
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = mkPkgs system;
          inherit (pkgs) lib;

          nodejs = pkgs.nodejs_22;
          pnpm = mkPnpm pkgs;

          cleanSource = lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              lib.cleanSourceFilter path type
              && !(builtins.elem (builtins.baseNameOf (toString path)) [
                ".direnv"
                "dist"
                "node_modules"
                "result"
              ]);
          };

          # Fuwari currently declares pnpm 9 in package.json. pnpm 10 would
          # otherwise download and run that old version automatically. Create
          # a sanitized build source that pins the secure Nix-provided pnpm and
          # removes the network-using `npx only-allow pnpm` preinstall guard.
          source = pkgs.runCommand "fuwari-source" {
            nativeBuildInputs = [ pkgs.jq ];
          } ''
            mkdir -p "$out"
            cp -R ${cleanSource}/. "$out/"
            chmod -R u+w "$out"

            jq --arg packageManager "pnpm@${pnpm.version}" \
              '.packageManager = $packageManager | del(.scripts.preinstall)' \
              "$out/package.json" > "$out/package.json.tmp"
            mv "$out/package.json.tmp" "$out/package.json"
          '';
        in
        {
          default = pkgs.stdenv.mkDerivation (finalAttrs: {
            pname = "fuwari-site";
            version = "0.1.0";
            src = source;

            nativeBuildInputs = [
              nodejs
              pnpm
              pkgs.pnpmConfigHook
              pkgs.pagefind
            ];

            # Replace lib.fakeHash after the first failed `nix build`.
            pnpmDeps = pkgs.fetchPnpmDeps {
              inherit (finalAttrs) pname version src;
              inherit pnpm;
              fetcherVersion = 4;
              hash = lib.fakeHash;
            };

            ASTRO_TELEMETRY_DISABLED = "1";

            buildPhase = ''
              runHook preBuild

              # Equivalent to Fuwari's build script, but use Nix's Pagefind
              # binary instead of the downloaded platform binary.
              pnpm exec astro build
              pagefind --site dist

              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall

              mkdir -p "$out"
              cp -r dist/. "$out/"

              runHook postInstall
            '';
          });
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = mkPkgs system;
          pnpm = mkPnpm pkgs;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.nodejs_22
              pnpm
              pkgs.pagefind
            ];

            ASTRO_TELEMETRY_DISABLED = "1";

            shellHook = ''
              export PATH="$PWD/node_modules/.bin:$PATH"

              # Fuwari's package.json may still name pnpm 9. Prevent pnpm 10
              # from downloading and handing control back to that old version.
              export npm_config_manage_package_manager_versions=false
              export PNPM_CONFIG_MANAGE_PACKAGE_MANAGER_VERSIONS=false

              echo "Fuwari dev shell: pnpm ${pnpm.version}"
              echo "Run 'pnpm install', then 'pnpm dev'."
            '';
          };
        }
      );

      formatter = forAllSystems (
        system:
        let
          pkgs = mkPkgs system;
        in
        pkgs.nixfmt-rfc-style
      );
    };
}
