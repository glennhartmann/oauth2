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
              "oauth2-0.0.2" = "sha256-ltguj0sgOmeCXws+JIaVI5+f4rk1IVZKSCoAX/acN74=";
            };
          };
        };
        all = pkgs.symlinkJoin {
          name = "all";
          paths = [
            oauth2
            oauth2-cli
          ];
        };
        oauth2-shell = pkgs.mkShell {
          inputsFrom = [
            oauth2
            oauth2-cli
          ];
          packages = with pkgs; [
            clippy
            rustfmt
          ];
        };
      in
      {
        packages = {
          inherit oauth2 oauth2-cli all;
          default = oauth2;
        };
        devShells = {
          inherit oauth2-shell;
          default = oauth2-shell;
        };
      }
    );
}
