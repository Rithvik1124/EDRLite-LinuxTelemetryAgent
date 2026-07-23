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
          hardeningDisable = [ "all" ];
 
          packages = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            rust-analyzer

            pkg-config
            gcc

            llvmPackages.clang
            llvm

            linuxHeaders
            glibc.dev

            elfutils
            cmake
            openssl
            curl
          ];

          shellHook = ''
            export BPF_SYSROOT=${pkgs.linuxHeaders}
            export BPF_INCLUDE=${pkgs.linuxHeaders}/include

            export CFLAGS="-I${pkgs.linuxHeaders}/include \
                          -I${pkgs.glibc.dev}/include"

            export BPF_CFLAGS="$CFLAGS"
          '';
        };
      });
}