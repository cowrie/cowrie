# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

{
  description = "Cowrie SSH/Telnet honeypot";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          python = pkgs.python3;
        in
        {
          default = self.packages.${system}.cowrie;

          cowrie = python.pkgs.buildPythonApplication {
            pname = "cowrie";
            version = "3.0.5-${self.shortRev or "dirty"}";
            pyproject = true;
            src = self;

            # setuptools-scm needs git metadata the nix source tree lacks.
            env.SETUPTOOLS_SCM_PRETEND_VERSION = "3.0.5";

            build-system = with python.pkgs; [
              setuptools
              setuptools-scm
            ];

            # pyproject.toml pins exact versions; build against what nixpkgs has.
            pythonRelaxDeps = true;

            dependencies = with python.pkgs; [
              attrs
              bcrypt
              cryptography
              hyperlink
              idna
              lark
              packaging
              pyasn1
              pyasn1-modules
              service-identity
              treq
              twisted
            ];

            checkPhase = ''
              runHook preCheck
              PYTHONPATH=src:$PYTHONPATH ${python.interpreter} -m unittest discover -s src/cowrie/test -t src
              runHook postCheck
            '';

            meta = {
              description = "SSH/Telnet honeypot";
              homepage = "https://www.cowrie.org/";
              license = nixpkgs.lib.licenses.bsd3;
              mainProgram = "cowrie";
            };
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          # The venv itself is managed by direnv (`layout python`) and
          # `pip install -e '.[dev]'`; the shell only supplies the interpreter.
          default = pkgs.mkShell {
            packages = [ pkgs.python3 ];
            env.PYTHONUNBUFFERED = "1";
            env.PYTHONDEVMODE = "1";
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = nixpkgs.lib.getExe self.packages.${system}.cowrie;
        };
      });
    };
}
