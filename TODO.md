<!--
SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>

SPDX-License-Identifier: BSD-3-Clause
-->

# TODO

- Exec-channel stdin line mode treats control bytes (CTRL-C, CTRL-D,
  backspace/delete) as a tty would even when the client requested no pty;
  in a plain pipe real bash sees them as literal bytes. Make the handling
  conditional on the pty request if the fidelity gap ever matters.

- A redirection onto a honeyfs file or a download starts an empty file:
  `echo x >> /etc/hosts` or `wget -O a; echo x >> a` leaves the emulated
  file holding only `x`. The stored sample stays intact. Copy the old
  content first for `>>` if this ever matters.

- SFTP `open` calls `mkfile`, so an append or partial overwrite loses the
  old content and resets owner and mode.

- Downloads (wget, curl, tftp, ftpget, scp, SFTP) still point the emulated
  file into the hash store; redirects treat those as read-only. Giving
  them connection backing files too, as redirects have, would keep the
  emulated filesystem fully apart from artifact storage.

- `ruff format` would reformat 20 files outside the exec-shell work
  (`ruff format --check src/cowrie` lists them); run it tree-wide in a
  formatting-only commit.
