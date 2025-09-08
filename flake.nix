{
  description = "Wavy is a toolset for running GUI applications on Kubernetes";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    git-hooks-nix = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.git-hooks-nix.flakeModule
      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      perSystem =
        {
          pkgs,
          system,
          config,
          ...
        }:
        {
          packages = rec {
            wavy = pkgs.buildGoModule rec {
              pname = "wavy";
              version = "0.0.1";
              src = ./.;
              vendorHash = null;
              checkFlags = [ "-skip=^TestE2E" ];
              CGO_ENABLED = 0;
              ldflags = [
                "-s -w -X github.com/wavyland/wavy/version.Version=${version}"
              ];

              meta = {
                description = "Wavy is a toolset for running GUI applications on Kubernetes";
                mainProgram = "wavy";
                homepage = "https://github.com/wavyland/wavy";
              };
            };

            default = wavy;
          };

          pre-commit = {
            check.enable = true;
            settings = {
              src = ./.;
              hooks = {
                actionlint.enable = true;
                nixfmt-rfc-style.enable = true;
                gofmt.enable = true;
                gofmt.excludes = [ "vendor" ];
                golangci-lint.enable = true;
                golangci-lint.excludes = [ "vendor" ];
                golangci-lint.extraPackages = [ pkgs.go ];
                govet.enable = true;
                govet.excludes = [ "vendor" ];
                yamlfmt.enable = true;
                yamlfmt.args = [
                  "--formatter"
                  "indentless_arrays=true"
                ];
                yamlfmt.excludes = [
                  ".github"
                  "vendor"
                ];
              };
            };
          };

          devShells = {
            default = pkgs.mkShell {
              inherit (config.pre-commit.devShell) shellHook;
              packages =
                with pkgs;
                [
                  go
                  kind
                  kubectl
                ]
                ++ config.pre-commit.settings.enabledPackages;
            };
          };
        };
    };
}
