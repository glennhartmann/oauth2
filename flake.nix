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
        oauth2-shell = pkgs.mkShell {
          inputsFrom = [ oauth2 ];
          packages = with pkgs; [
            clippy
            rustfmt
          ];
        };
      in
      {
        packages = {
          inherit oauth2;
          default = oauth2;
        };
        devShells = {
          inherit oauth2-shell;
          default = oauth2-shell;
        };
      }
    );
}
