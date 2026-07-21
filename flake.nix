{
  description = "Rust development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        devShells.default = pkgs.mkShell {  
          packages = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            rust-analyzer
            pkg-config
            gcc
            gdb
            lldb
            cargo-watch
            cargo-edit
            bacon
            openssl
            cyrus_sasl
            cmake
            llvmPackages.clang-unwrapped
            curl
            elfutils
            llvm
            linuxHeaders
          ];
        };
      });
}