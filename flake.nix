{
  description = "Description for the project";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    treefmt = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    laplace = {
      url = "github:dysthesis/laplace";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {flake-parts, ...}: let
    inherit (inputs.nixpkgs) lib;
  in
    flake-parts.lib.mkFlake {
      inherit inputs;
      specialArgs = {inherit lib;};
    } {
      imports = [
        inputs.treefmt.flakeModule
      ];
      systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin"];
      perSystem = {
        pkgs,
        inputs',
        ...
      }: {
        devShells.default = pkgs.mkShell {
          name = "The Moo Deng Fuzzer";
          packages = with pkgs; [
            radare2

            # Python scripting
            (python3.withPackages (ps:
              with ps; [
                r2pipe
                pillow
              ]))
            pyright
            black

            # C
            clang-tools

            # Standard nix stuff
            statix
            deadnix
            nil
            alejandra

            # rop
            one_gadget
            inputs'.laplace.packages.ropr
          ];
          shellHook =
            /*
            sh
            */
            ''
              alias gdb=pwndbggef
            '';
          NIX_LD_LIBRARY_PATH = lib.makeLibraryPath (with pkgs; [
            stdenv.cc.cc
            openssl
          ]);
        };

        treefmt = {
          projectRootFile = "flake.nix";
          programs = lib.fold (curr: acc: acc // {${curr}.enable = true;}) {} [
            "prettier"
            "alejandra"
            "statix"
            "deadnix"
            "black"
          ];
        };
      };
    };
}
