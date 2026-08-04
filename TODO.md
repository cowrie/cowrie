<!--
SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>

SPDX-License-Identifier: BSD-3-Clause
-->

# TODO

- Double `processEnded` on late channel EOF: after a session's process has
  ended (exec command finished, `exit` in a shell), a channel EOF arriving
  afterwards delivers a second `processEnded` through the leftover shell on
  the cmdstack. `HoneyPotExecProtocol.eofReceived` guards only the
  stdin-line-mode instance. Root-cause fix: a fire-once process-end helper
  on the protocol, used by `HoneyPotShell._finish` / `_terminate` /
  `eofReceived`, `HoneyPotCommand.exit`, and `timeoutConnection`.

- Exec-channel stdin line mode treats control bytes (CTRL-C, CTRL-D,
  backspace/delete) as a tty would even when the client requested no pty;
  in a plain pipe real bash sees them as literal bytes. Make the handling
  conditional on the pty request if the fidelity gap ever matters.

- `ruff format` would reformat 20 files outside the exec-shell work
  (`ruff format --check src/cowrie` lists them); run it tree-wide in a
  formatting-only commit.
