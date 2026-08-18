{
  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs;
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-compat, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
        oauth2 = pkgs.rustPlatform.buildRustPackage {
          pname = manifest.name;
          version = manifest.version;
          src = builtins.path { path = ./.; name = "oauth2"; };

          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };
        cli-manifest = (pkgs.lib.importTOML ./cli/Cargo.toml).package;
        oauth2-cli = pkgs.rustPlatform.buildRustPackage {
          pname = cli-manifest.name;
          version = cli-manifest.version;
          src = builtins.path { path = ./cli; name = "oauth2-cli"; };

          cargoLock = {
            lockFile = ./cli/Cargo.lock;

            outputHashes = {
              "oauth2-0.0.3" = "sha256-4aap4FwENrIZdx8mn1olipljbpbv3FnL4hi90eBn2Dw=";
            };
          };
        };
        simple-manifest = (pkgs.lib.importTOML ./simple/Cargo.toml).package;
        oauth2-simple = pkgs.rustPlatform.buildRustPackage {
          pname = simple-manifest.name;
          version = simple-manifest.version;
          src = builtins.path { path = ./simple; name = "oauth2-simple"; };

          cargoLock = {
            lockFile = ./simple/Cargo.lock;

            outputHashes = {
              "oauth2-0.0.3" = "sha256-4aap4FwENrIZdx8mn1olipljbpbv3FnL4hi90eBn2Dw=";
            };
          };
        };
        all = pkgs.symlinkJoin {
          name = "all";
          paths = [
            oauth2
            oauth2-cli
            oauth2-simple
          ];
        };
        oauth2-shell = pkgs.mkShell {
          inputsFrom = [
            oauth2
            oauth2-cli
            oauth2-simple
          ];
          packages = with pkgs; [
            clippy
            rustfmt
          ];
        };
      in
      {
        packages = {
          inherit oauth2 oauth2-cli oauth2-simple all;
          default = all;
        };
        devShells = {
          inherit oauth2-shell;
          default = oauth2-shell;
        };
      }
    );
}
