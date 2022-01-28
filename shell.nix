{ pkgs ? import (fetchTarball https://github.com/nixos/nixpkgs/archive/nixpkgs-unstable.tar.gz) {} }:

let
  customPython = pkgs.python38.buildEnv.override {
    extraLibs = [ pkgs.python38Packages.ipython pkgs.python38Packages.pwntools ];
  };
in
pkgs.mkShell {
  nativeBuildInputs = [ pkgs.python-language-server ];
  buildInputs = [ customPython pkgs.gdb pkgs.pwndbg pkgs.ccls pkgs.pkgsi686Linux.glibc.dev pkgs.pkgsi686Linux.gcc ];
  shellHook = ''
    alias pwntools-gdb=pwndbg
  '';
}
