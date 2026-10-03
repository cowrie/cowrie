<!--
SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>

SPDX-License-Identifier: BSD-3-Clause
-->

# TODO

- Exec-channel stdin line mode treats control bytes (CTRL-C, CTRL-D,
  backspace/delete) as a tty would even when the client requested no pty;
  in a plain pipe real bash sees them as literal bytes. Make the handling
  conditional on the pty request if the fidelity gap ever matters.

- `ruff format` would reformat 20 files outside the exec-shell work
  (`ruff format --check src/cowrie` lists them); run it tree-wide in a
  formatting-only commit.
