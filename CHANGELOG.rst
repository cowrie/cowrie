.. SPDX-FileCopyrightText: 2014-2025 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Release Notes
#############

Unreleased
**********

**SECURITY AND HARDENING:**

* ``printf`` caps the output one invocation builds in memory at 1 MiB.
  Before, a short command such as ``printf '%*d' 700000000 1`` could
  use up the process's memory and get Cowrie killed. A field width or
  precision past the cap now fails the way bash fails one past the C
  int range. Reported by Davide S. Rosa (@davide-s-rosa).
* Each session's TTY log has a size limit, set by the new
  ``[honeypot] ttylog_limit_size`` option. The default is 10 MiB. A
  session that reaches the limit is disconnected. Set the option to 0
  to turn the limit off. Reported by Davide S. Rosa (@davide-s-rosa).
* A TTY log that cannot be opened, written or closed no longer breaks
  the session. Cowrie logs the error once and the session continues
  without a recording. Before, a full disk made every new exec request
  fail until an operator freed space. Reported by Davide S. Rosa
  (@davide-s-rosa).
* The new ``[honeypot] ttylog_min_free`` option keeps a minimum of free
  space on the filesystem that holds the TTY logs. Below it, sessions
  run without a TTY log. The default is 0, which turns the check off.

**BUG FIXES:**

* SSH key exchange messages that do not match the negotiated algorithm,
  or arrive before KEXINIT, are answered with SSH_MSG_UNIMPLEMENTED and
  logged as ``cowrie.client.kex_unexpected`` instead of crashing the
  connection.

**DEPENDENCIES:**

* txmongo 26.0.0 and mysql-connector-python 26.10.0 for the output
  plugins.


Release 3.1.5 (2026-10-31)
**************************

**NEW FEATURES:**

* The shell evaluates ``$((...))`` arithmetic expansion.
* The shell has a ``read`` builtin.

**BUG FIXES:**

* ``$$`` expands to the shell's process ID.
* ``set`` sets the positional parameters from its operands.
* A lost terminal is logged once per command, not once per write.
* Backend pool: a guest that fails to boot is reported and retried,
  instead of stopping the whole Cowrie process.
* VirusTotal: an empty success response when adding to a collection is
  accepted.

**DEPENDENCIES:**

* Twisted 26.10.0.


Release 3.1.4 (2026-10-24)
**************************

**NEW FEATURES:**

* The shell reads multi-line input like bash. An unfinished ``if``,
  ``for``, ``while``, ``case``, ``{`` or ``(``, an open quote, ``$(`` or
  backtick, and a line ending in ``\``, ``|``, ``&&`` or ``||`` continue
  on the next line at a ``> `` prompt. ``bash -c``, scripts and exec
  commands that end inside one report bash's unexpected end of file.
* Here-documents (``<<EOF``, ``<<-EOF``, quoted delimiters) and
  here-strings (``<<<word``) feed a command's stdin. An unquoted body is
  expanded as usual. The new ``[shell] max_heredoc_size`` option caps a
  body's size.
* **New output plugin**: MalwareBazaar. It uploads downloaded and
  uploaded files once per SHA-256 and reports each result as a
  ``cowrie.malwarebazaar.submitted`` event.

**BUG FIXES:**

* ``curl`` accepts options after the URL.
* ``$@``, ``$#`` and ``$1`` work in scripts and outside functions.
* ``"$@"`` keeps each positional parameter a separate word.
* Braced special parameters such as ``"${@}"`` are expanded.
* ``grep -i`` is supported.

**DEPENDENCIES:**

* cryptography 50.0.2.


Release 3.1.3 (2026-10-15)
**************************

**BUG FIXES:**

* Running a file by path (``./file``) needs an execute bit, as on a
  real system. Without one the shell reports "Permission denied" with
  status 126. ``sh file`` still works.
* A failed redirection skips the command and sets status 1, as in bash.
* ``scp -d`` with no target directory no longer crashes.
* ``mv`` of a symbolic link renames the link, not its target.
* The ``csirtg`` and ``slack`` outputs read the event's ``protocol``
  field. Before, they read a key that events do not carry.

**INTERNAL:**

* The ssh and telnet packages sit below the shell package, and modules
  no longer read the configuration at import time.


Release 3.1.2 (2026-10-12)
**************************

**BREAKING CHANGES - ACTION REQUIRED:**

* **Output plugin dependencies**: the ``mongodb`` output needs
  ``txmongo`` instead of ``pymongo``, and the ``redis`` output needs
  ``txredisapi`` instead of ``redis``. Install them from
  ``requirements-output.txt`` if you use these outputs.

**BUG FIXES:**

* The ``rmq``, ``rethinkdblog``, ``mongodb`` and ``redis`` outputs no
  longer block the reactor. A slow or unreachable database froze every
  session. They now use Twisted-native clients. The ``rmq`` output
  imports again on current Twisted.
* Unquoted expansions are split into words and empty ones vanish, as in
  bash. Quoted or expanded words are never read as redirections.
* ``cat``, ``cd``, ``rm``, ``rmdir``, ``mkdir``, ``touch``, ``cp``,
  ``mv`` and other commands report failures through the exit status, as
  GNU tools do, so ``||`` and ``&&`` take the right branch.
* A bare ``sync`` succeeds silently.
* A command's scheduled calls are cancelled when the client disconnects.
* Every SSH disconnect reason is logged on one line.
* A client that sends 4 KiB without an SSH identification line is
  disconnected.

**DEPENDENCIES:**

* cryptography 50.0.1.


Release 3.1.1 (2026-10-03)
**************************

**BUG FIXES:**

* A session's process ends once, whatever ends it.
* ``reboot`` and ``shutdown`` no longer crash after a disconnect.
* ``chmod`` applies symbolic modes such as ``u+x`` and ``go-w``, and
  applies to every file a ``*`` matches.
* ``ls`` names a file argument the way it was typed, and reports a
  missing argument the way GNU ``ls`` does.


Release 3.1.0 (2026-10-02)
**************************

**BREAKING CHANGES - ACTION REQUIRED:**

* **Python 3.10 no longer supported**: Minimum Python version is now 3.11.

**NEW FEATURES:**

* **New shell commands**: ``sed`` and ``tr``.
* The emulated machine now booted before Cowrie started. ``uptime``,
  ``/proc/uptime`` and ``last`` count from that boot, so a restarted
  honeypot no longer reports a few seconds of uptime. The new
  ``[honeypot] boot_offset`` option sets the gap in seconds. When unset,
  Cowrie picks a value between one and ninety days once per process.

**BUG FIXES:**

* Shell errors look more like bash: syntax errors and "command not
  found" go to stderr, carry the right prefix for interactive and
  script shells, and name the line number in scripts.
* A stray closing word such as ``fi`` or ``done`` is a syntax error,
  reported when execution reaches its line.
* Scripts that cannot run exit 126, and missing interpreters exit 127.
  The error names the script the way the attacker typed it.
* The output of a shell that a command starts is captured.
* ``printf`` implements its format conversions.
* ``awk -F`` accepts patterns with spaces and prints real output.
* ``head`` and ``tail`` accept the GNU option forms and read piped input.
* ``lscpu`` describes the same CPU as ``/proc/cpuinfo``.
* ``esac`` is a keyword only in command position.
* ``"\\"`` inside double quotes reads as one backslash.
* The ``socketlog`` output sends events on the reactor instead of
  blocking in ``write()``.
* Idle LLM sessions time out after 300 seconds by default, the same as
  the shell.


Release 3.0.15 (2026-09-19)
***************************

**BREAKING CHANGES - ACTION REQUIRED:**

* **VirusTotal collections**: ``[output_virustotal] collection`` is
  replaced by ``collection_id``. Copy the ID from the collection's URL
  in the VirusTotal web interface.

**SECURITY AND HARDENING:**

* The shell grammar is unambiguous, so crafted input can no longer make
  the parser run for minutes. New ``[shell] parse_timeout_seconds`` and
  ``gc_collect_threshold`` options limit what is left. Pipelines and
  redirections are real.

**BUG FIXES:**

* An empty password in ``userdb.txt`` is accepted.
* ``finger`` reads ``/etc/passwd`` line by line.
* ``cut`` reports a malformed field list instead of crashing.
* ``cp`` and ``mv`` report an empty destination instead of crashing.
* Created directories get directory modes.
* ``rmdir`` of a missing directory reports ENOENT.
* Symbolic link checks look at the link, not its target.
* Database outputs close their connection pool only when it runs.


Release 3.0.14 (2026-09-07)
***************************

**SECURITY AND HARDENING:**

* Attacker text is escaped in Telegram messages.

**BUG FIXES:**

* An exec command that is not valid UTF-8 still runs.
* ``rmdir`` and ``touch`` process all their arguments.
* ``ps`` separates COMMAND arguments with spaces.
* The shell prompt is written as UTF-8.
* Tab completion survives undecodable input and a missing window size.
* ``curl`` handles an unknown content length.
* ``grep -m`` sets a maximum match count.
* ``printf`` survives a malformed escape.
* The Prometheus output publishes and resets its source-IP windows.
* More malformed LLM prompt templates are tolerated.
* The ``cowrie.urlhaus.submitted`` event ID is registered.


Release 3.0.13 (2026-08-23)
***************************

**NEW FEATURES:**

* **New output plugin**: URLhaus.

**SECURITY AND HARDENING:**

* ``wget``, ``curl`` and ``ftpget`` validate every redirect hop and
  connect to the address they validated.
* IPv6 download targets are reported as unreachable.
* CEF extension values are escaped.
* A bad SSH packet length is no longer answered with "Packet corrupt",
  which identified Cowrie.

**BUG FIXES:**

* Proxy mode: SFTP messages are reassembled by their length prefix,
  message types above 127 are framed correctly, the frontend no longer
  sends on a closed transport, and the backend address is logged as a
  string.
* SFTP reports the real size of an upload, and closes the file before
  renaming it.
* The ``sqlite`` output stores file uploads and session input, and holds
  a single connection.
* The ``jsonlog`` output appends to its logfile instead of truncating it.
* The ``rethinkdblog`` output reads event timestamps as UTC.
* VirusTotal submits URLs it has not seen before.
* The MISP and DShield outputs release session state when the session
  closes.
* An output plugin that failed to start is not stopped.
* ``curl`` and ``wget`` report a malformed URL port.
* ``sh`` survives an empty ``-c`` argument and non-UTF-8 stdin.
* ``grep`` reports an invalid pattern.
* ``mkdir`` processes all its arguments.
* ``ftpget`` keeps downloading after CTRL-C.
* An empty ``$@`` or ``$*`` expands to no words.
* ``dig`` prints real UTC time; ``base64`` encodes interactive input as
  UTF-8; a non-numeric ``COLUMNS`` falls back to the default width.
* ``createfs`` applies its ``-v`` and ``-p`` flags; ``fsctl`` rejects a
  non-numeric uid or gid.
* TTY logs that are not valid UTF-8 convert to asciinema.

**INTERNAL:**

* The Docker container uses a fixed uid.


Release 3.0.12 (2026-08-04)
***************************

**SECURITY AND HARDENING:**

* The new ``[shell] max_input_size`` option caps the size of shell input
  fed to the parser.
* The Docker image no longer ships pip, setuptools and wheel.

**DEPENDENCIES:**

* cryptography 50.0.0.


Release 3.0.11 (2026-07-31)
***************************

**BREAKING CHANGES - ACTION REQUIRED:**

* **Rate-limit options moved**: the ``wget``, ``curl`` and ``nc``
  rate-limit options are read from ``[shell]``, not ``[honeypot]``.
  Move them if you set them.
* The ``crashreporter`` output plugin is removed, along with its
  ``[output_crashreporter]`` config section. It reported Python
  exceptions to api.cowrie.org and was disabled by default.

**NEW FEATURES:**

* **HAProxy PROXY protocol**: listen endpoints accept a ``haproxy:``
  prefix, so Cowrie logs the attacker's address behind a load balancer.
* ``grep`` reads stdin when no files are given.
* ``wget -O-`` and ``curl -o -`` write the download to stdout.
* A Nix flake for building and developing Cowrie.

**SECURITY AND HARDENING:**

* Downloads that pass ``download_limit_size`` are aborted.
* ``ftpget`` and ``tftp`` have a rate limit, the size limit and the
  outbound bind address. ``tftp`` validates the address it contacts.
* ``nc`` connects to the address it validated and no longer blocks the
  reactor.
* The outbound rate limiter treats host names case-insensitively.
* scp upload parsing is hardened. ``[shell] scp_max_files_per_session``
  caps uploads per session.
* Attacker bytes that are not valid UTF-8, malformed telnet input, and
  out-of-sequence keyboard-interactive responses no longer crash the
  session.
* SSH channel requests and window adjustments for unknown or closed
  channels are ignored.
* The LLM backend is hardened against attacker input and runaway API
  use.
* The Docker image has reproducible build metadata and a hardened
  ``docker-compose.yml``.

**BUG FIXES:**

* Command substitution waits for slow commands such as ``wget`` and
  carries their status into ``$?``.
* Each shell has its own working directory and user identity.
* Long pipelines no longer recurse per stage, and a stage that
  finishes later is still fed.
* A bare ``=`` is a command name, not an assignment.
* An empty symbolic link target is a broken link.
* ``AuthRandom`` lets returning attackers log in again.
* The emulated filesystem uses ``/``-separated paths on every host, which
  fixes SFTP directory listings and file operations on Windows.
* Proxy mode flushes buffered frontend packets.
* Output plugins handle failed HTTP requests, including GreyNoise.
* Database outputs survive error-handler crashes and NULL string rows.
* The CEF and Slack outputs match the event IDs Cowrie really emits.
  Slack builds its client once and honors its ``timestamp`` option.
* The ``reversedns`` output caches results.
* scp stdin lines are logged as session input.

**INTERNAL:**

* Sessions share one copy-on-write honeyfs tree instead of a deep copy
  each.


Release 3.0.10 (2026-07-26)
***************************

**NEW FEATURES:**

* **New output plugin**: Kafka, based on ``aiokafka``. It needs the
  asyncio reactor. It reconnects, buffers events while disconnected,
  and flushes them at shutdown.

**BUG FIXES:**

* Telnet logins work with bare-CR line endings, such as PuTTY's.
* Malformed telnet IAC traffic no longer logs a traceback.


Release 3.0.9 (2026-07-23)
**************************

**SECURITY AND HARDENING:**

* Outbound downloads bind to ``[honeypot] out_addr``, so they do not
  leak the server's own address.
* IPv4-compatible IPv6 addresses are blocked as outbound targets.
* ``tftp`` resolves the target host name before sending.

**BUG FIXES:**

* ``bash`` as the exec command reads the channel's stdin, and the shell
  exits with the last command's status at EOF.
* ``curl`` and ``wget`` handle a TCP connect timeout, and no longer
  hang the session when the request fails at once.
* Proxy mode drops OpenSSH host-key rotation requests.


Release 3.0.8 (2026-07-20)
**************************

**SECURITY AND HARDENING:**

* Outbound targets that are not globally routable are blocked,
  including IPv4-mapped and embedded IPv4 IPv6 forms.


Release 3.0.7 (2026-07-20)
**************************

**NEW FEATURES:**

* The shell supports the ``exec`` builtin.

**BUG FIXES:**

* The PostgreSQL output works with restricted sequence permissions and
  no longer fails with "no results to fetch".
* A packet sent after the transport is gone no longer crashes.


Release 3.0.6 (2026-07-11)
**************************

**NEW FEATURES:**

* New ``[honeypot] log_level`` option sets the diagnostic verbosity of
  ``cowrie.log`` -- and of stdout in foreground/Docker mode -- (default
  ``info``), with per-subsystem overrides via ``log_level_<namespace>``
  (e.g. ``log_level_cowrie.ssh = debug``) or the matching
  ``COWRIE_HONEYPOT_LOG_LEVEL_*`` environment variables. Rendered
  attacker-event lines (``cowrie.events``) keep an ``info`` floor unless
  explicitly overridden. Structured event output (cowrie.json,
  databases) is unaffected.
* Lines typed while a command runs are parsed and logged as
  ``cowrie.command.input``.

**SECURITY AND HARDENING:**

* Malformed SSH packets are dropped and logged instead of crashing the
  connection.

**BUG FIXES:**

* Async commands in scripts run one after another.
* ``exit`` inside a command substitution keeps the session alive, and
  late download callbacks after exit are harmless.
* Exec channels reset the idle timeout on stdin, and ``cat`` redirects
  capture exec stdin.
* The ``jsonlog`` output writes each event in a single call, so it
  survives log rotation.
* Host names behind a CNAME and AAAA records resolve correctly.
* EOF and CLOSE for already-closed SSH channels are ignored.
* Captured logs are renamed correctly on Windows.
* ``wget`` no longer divides by zero when computing speed, and logs
  errors cleanly.

**INTERNAL:**

* Events go through a session-scoped ``EventLog`` and a central
  dispatcher. Output plugins emit enrichment events through
  ``Output.dispatch()``. See docs/EVENT_PIPELINE.rst.
* Diagnostic logging converted from the legacy ``twisted.python.log``
  API to per-class ``twisted.logger.Logger`` instances with namespaces
  and levels; messages are lazy PEP-3101 format strings with runtime
  values passed as data (see docs/EVENT_PIPELINE.rst). The backend
  pool's session-less emitters dropped their vestigial ``eventid=``
  markers and are plain diagnostics: pool bookkeeping is
  infrastructure, not attacker behavior, and never reached the output
  plugins.

**DEPENDENCIES:**

* ``treq`` upgraded to 26.7.0; ``requests`` and ``urllib3`` dropped.


Release 3.0.5 (2026-06-27)
**************************

**NEW FEATURES:**

* **Shell scripting**: ``if``, ``while``, ``until``, ``for`` and
  ``case``, the ``test`` / ``[`` builtin, real exit statuses, ``$?``,
  ``&&`` and ``||``, and ``exit N``. Uploaded scripts run through the
  same parser. The exit status is reported to the SSH client.
* **Shell parser**: Lark is the only shell parser. It supports ``&>``
  and ``&>>`` redirects.
* **New shell command**: ``su``.
* The ``textlog`` output can write OCSF records (``format = ocsf``).

**SECURITY AND HARDENING:**

* Untrusted bytes are escaped when Cowrie logs SSH versions, KEXINIT
  data, credentials and proxy commands.
* A duplicate KEXINIT disconnects cleanly, and an invalid telnet IAC
  byte no longer crashes the connection.

**BUG FIXES:**

* Many shell fixes: exit statuses of subshells and pipelines, unset
  variable expansion, ``2>file`` against ``2 >file``, redirects with no
  target or to bad file descriptors, directories run as commands, and
  binary files passed to ``sh``.
* Download commands exit non-zero on failure and remove empty
  artifacts.
* SFTP reports emulated-filesystem errors correctly.
* VirusTotal comments on and collects uploads by file hash, and reuses
  an existing collection.
* A failed DNS lookup is logged at info level, and each telnet option
  negotiation once per connection.
* ``cowrie stop``, ``force-stop`` and ``status`` report a wrong
  directory up front.

**INTERNAL:**

* The Docker image is published only from release tags.

**DEPENDENCIES:**

* cryptography 49.0.0.


Release 3.0.4 (2026-06-22)
**************************

**BREAKING CHANGES - ACTION REQUIRED:**

* **Event field rename**: ``cowrie.session.closed`` and
  ``cowrie.log.closed`` report ``duration_ms`` as an integer number of
  milliseconds. The ``duration`` field is gone. It was a string for
  some transports and a float for others. Update dashboards and
  index mappings that read ``duration``.

**NEW FEATURES:**

* **New shell command**: ``chpasswd``.
* The DShield output records the last command of a session.

**BUG FIXES:**

* Exec channels deliver stdin EOF from the channel and send bare LF
  without a PTY. Commands with no input see EOF.
* Shell variables persist, and exported variables are kept apart.
* An unset or empty ``PATH`` no longer breaks command dispatch.
* A directory or a missing path run as a command reports EISDIR or
  ENOENT.
* scp uploads are stored as file content, not wire framing.
* Telnet NAWS negotiation is restored, and negotiation retries no
  longer crash at teardown.
* Busybox applets honor output redirection.
* An unknown ``auth_class`` falls back to ``UserDB``.
* The MISP output looks up samples by MD5.
* Failed ``wget`` and ``curl`` downloads leave no temp files.

**DEPENDENCIES:**

* cryptography 48.0.1.


Release 3.0.3 (2026-06-08)
**************************

**NEW FEATURES:**

* **New output plugin**: Signal messenger.


Release 3.0.2 (2026-06-04)
**************************

* Dependency updates only.


Release 3.0.1 (2026-05-31)
**************************

**BUG FIXES:**

* Text commands honor ``txtcmds_path``.


Release 3.0.0
*************

**BREAKING CHANGES - ACTION REQUIRED:**

* **State directory layout is now cwd-driven.** ``cowrie start`` no
  longer ``chdir``\s to a script-derived "root" path. The current
  working directory is the cowrie state directory: ``./etc/cowrie.cfg``
  is the config, ``./var/log/cowrie/`` holds logs, ``./var/run/`` holds
  the PID file. Run all cowrie commands (``start``, ``stop``, ``restart``,
  ``status``) from the same directory.

* **New ``cowrie init`` command.** Pip-install operators run ``cowrie
  init`` once in their chosen state directory to materialise
  ``./etc/cowrie.cfg`` from the bundled template and create the
  ``var/{log/cowrie,lib/cowrie,run}`` skeleton. Source-checkout users
  unaffected — the repo root counts as initialised via
  ``src/cowrie/data/etc/cowrie.cfg.dist``.

* **``cowrie start`` refuses to run without an init marker.** Looks
  for one of ``./etc/cowrie.cfg``, ``./etc/cowrie.cfg.dist``, or
  ``./src/cowrie/data/etc/cowrie.cfg.dist``. Prevents accidentally
  polluting the wrong directory with state files.

* **Top-level ``honeyfs/`` directory removed.** Its contents are now
  embedded in ``src/cowrie/data/fs.pickle`` as ``A_CONTENTS`` bytes.
  Operators with local customisations: keep your honeyfs files in a
  directory of your choice and set ``[honeypot] contents_path`` to it
  in ``cowrie.cfg``; per-file overrides still cascade on top of the
  bundled defaults.

* **Bundled ``cowrie.cfg.dist`` moved into the package.** The
  template is now at ``src/cowrie/data/etc/cowrie.cfg.dist`` and is
  loaded as the defaults layer automatically. Your operator config
  (``etc/cowrie.cfg``) only needs to contain the keys you want to
  override.

* **``[honeypot] data_path`` config key removed.** Settings that
  used ``${honeypot:data_path}/...`` (``filesystem``, ``processes``,
  ``config_files_path``) now read their bundled defaults from the
  package directly when left unset. Operators who set ``data_path``
  in their cowrie.cfg should set each derived path individually
  instead.

* **``[honeypot] contents_path`` is now unset by default.** Previously
  defaulted to ``honeyfs`` (the removed top-level directory). Leaving
  it unset serves all file contents from the pickle. Set it only when
  you want per-file overrides.

**CONFIGURATION CHANGES:**

* Bundled ``cowrie.cfg.dist`` has ``contents_path``, ``filesystem``,
  and ``processes`` commented out (each documents how to override).
* ``data_path`` removed from cfg.dist.

**DEPENDENCIES:**

* ``tftpy`` removed from runtime dependencies. The TFTP client
  (``cowrie/commands/tftp.py``) uses a Twisted ``DatagramProtocol``
  implementation; tftpy was never imported.

**INTERNAL:**

* New ``cowrie/shell/honeyfs.py`` module owns the per-process pickle
  cache. ``HoneyPotFilesystem`` instances now share a single
  ``pickle.load`` via ``honeyfs.get_tree()`` (deepcopied per session)
  instead of re-reading from disk on every connection.
* New ``cowrie/core/resources.py`` provides ``read_data_bytes`` and
  ``open_data_binary`` for accessing bundled ``cowrie.data``
  resources via ``importlib.resources``.
* ``createfs.py`` grew an ``EMBED_PATHS`` constant — paths whose
  bytes are baked into ``A_CONTENTS`` during the recursive walk.
* ``fsctl`` gained an ``embed <local-dir>`` command for bulk-loading
  file contents into an already-built pickle.
* ``Passwd`` and ``Group`` classes moved from class-body load to
  instance ``__init__``.
* ``backend_pool`` XML config templates now use a bundled-data cascade
  matching the honeyfs pattern. ``[backend_pool] config_files_path``
  is optional; unset falls through to bundled defaults via
  ``importlib.resources``.
* CI smoke tests for PyPI packages replaced the no-op ``twistd cowrie``
  invocation with checks that verify the entry point, bundled resources,
  ``cowrie init`` output, and the init-marker guard on ``cowrie start``.


Releases 2.9.1 -- 2.9.20
*************************

**NEW FEATURES:**

* **New shell commands**: ``cut``.
* **IPv6 support**: ``ifconfig`` and ``netstat`` now show Global Unicast
  Addresses; ``get_endpoints_from_section`` detects IPv6 listen addresses.
* **LLM proxy support**: the LLM backend reads ``HTTP_PROXY`` /
  ``HTTPS_PROXY`` environment variables for outbound requests.
* **LLM Anthropic provider**: Claude can now be used as an LLM backend
  alongside OpenAI. The context prompt sent to the model is configurable.
* **Shell script execution**: scripts created via output redirection
  (e.g. ``cat > script.sh``) can now be executed.
* **CVE-2026-24061 detection**: telnet NEW-ENVIRON exploit attempts are
  detected and logged; the honeypot emulates the vulnerable response.
* **OS fingerprint update**: default emulated OS bumped to Debian 12 /
  kernel 6.1.
* **SPDX / REUSE compliance**: all source files carry SPDX license
  headers; ``reuse lint`` passes in CI.

**BUG FIXES:**

* **SSRF protection bypass** in ``ftpget``, ``tftp``, and ``nc`` commands
  (reserved IP range checks were bypassable).
* ``chmod --help`` and ``--version`` were broken.
* ``chattr`` command was shadowed by a no-op stub.
* ``wget`` saved downloaded files to ``/`` instead of the session's cwd.
* ``playlog`` now shows output for exec sessions.
* File-descriptor redirection parsing handles more edge cases.
* Tab completion no longer errors on non-existing directories.
* ``backend_pool`` NAT errors in remote mode when the client protocol
  was not yet initialised or already closed.
* Telnet infinite recursion when ``onResult`` callback is ``None``.
* ``nc`` command: more realistic output and abuse-protection limits.

**INFRASTRUCTURE:**

* Docker base image upgraded to Debian 13 (trixie) / Python 3.13.
* Twisted bumped to 26.4.0 with stricter typing adopted.
* Malshare and Cuckoo output plugins ported from ``requests`` to ``treq``.
* Weekly automated release workflow added.
* Bundled ``fs.pickle`` now embeds file contents (``A_CONTENTS`` bytes).


Release 2.9.0
*************

**NEW FEATURES:**

* **LLM Backend**: New experimental backend that uses Large Language Models (such as OpenAI's GPT) to generate realistic shell responses. Instead of static command emulation, the LLM dynamically generates output for any command, making the honeypot more convincing and capable of handling unexpected inputs. See the `LLM documentation <https://docs.cowrie.org/en/latest/LLM.html>`_ for setup instructions.

**CONFIGURATION CHANGES:**

* New ``[llm]`` configuration section for LLM backend settings including API key, model selection, and response parameters.


Release 2.7.0
*************

**BREAKING CHANGES - ACTION REQUIRED:**

* Install Cowrie into your virtual environment with `pip install -e .` 
* **bin/ directory removed**: Scripts `asciinema`, `createfs`, `fsctl`, and `playlog` are no longer called from the `bin/` directory. 
* **Python 3.9 no longer supported**: Minimum Python version is now 3.10.
* **SQL schema update required**: If using MySQL/SQLite databases, run the migration script `docs/sql/update16.sql` to extend IP address fields for IPv6 support (VARCHAR length increased to 61 characters).
* **SSH-DSS key support removed**: The deprecated ssh-dss algorithm is no longer supported for improved security. Remove ssh-dss configuration if you use it.

**NEW FEATURES:**

* **New Output Plugins**:
  * PostgreSQL output plugin with automatic reconnection support
  * Prometheus metrics output plugin for monitoring and alerting
* **New Shell Commands**:
  * `find` command with basic options for file searching
  * `dig` command for DNS lookups
  * `git` command for version control simulation
  * `curl` command now supports HEAD requests with `-I` option
* **Enhanced Security**:
  * Network blocking for outbound connections from wget/curl/nc to reserved IP ranges
  * Null byte password protection to prevent authentication bypasses
  * Updated SSH algorithms and key management for better security posture
* **Proxy Mode Improvements**:
  * SFTP file transfers now logged and captured in proxy mode
  * Better SSH factory handling for improved stability

**CONFIGURATION CHANGES:**

* New configuration options available for:
  * PostgreSQL output plugin settings
  * Prometheus metrics endpoint configuration
  * Network blocking controls for command simulation

**INFRASTRUCTURE UPDATES:**

* **Docker**:
  * Improved local build support
  * Container signing with Cosign for supply chain security
  * Updated base images and metadata
* **Build System**:
  * Migrated to setuptools-scm for automatic version management
  * PyPI package publishing now automated as trial for future development
* **Dependencies**:
  * Twisted updated to 25.5.0
  * Elasticsearch client updated to 9.x
  * Various security updates across all dependencies

**IMPROVED FEATURES:**

* Enhanced MISP output plugin with overcuriosity protection and better threat intelligence integration
* Simplified Slack output formatting for better readability
* Better shell command substitution and subshell execution
* Improved error handling in wget with explicit timeouts
* ECS-compliant Logstash configuration template
* Enhanced history handling in shell sessions

**DEVELOPMENT:**

* Added Python 3.14 development version support
* Added PyPy 3.11 support
* Improved test coverage and CI/CD pipelines

Release 2.6.0
*************
* Breaking change: default location of static files has moved from share/cowrie to src/cowrie/data
* In the configuration file the `share_path` is now `data_path`
* Python 3.12 support
* Python 3.13 support
* Pypy 3.10 support
* Python 3.8 no longer supported
* Twisted 24.10 support
* Docker builds now use Debian 12 Bookworm
* New output plugins: Oracle, Remote Syslog, Axiom
* New commands: finger, groups, locate, lspci
* Cowrie can now be installed with `pip install -e`

Release 2.5.0
*************

* Datadog output module (Fred Baguelin <frederic.baguelin@datadoghq.com>)
* General improvements to shell expansion handling
* New version of Twisted supported
* Python 3.11 support
* Pypy 3.9 support
* Add session type to Telegram output

Release 2.4.0
*************

* Deprecate Python 3.7
* Early support for Python 3.11
* ThreatJammer output plugin (@diegoparrilla)
* Telegram output plugin (@Louren)
* Discord output plugin (@CyberSparkNL)
* Updated mongodb output plugin
* Dependency upgrades
* Docker repo merged with this one
* `wget` and `curl` rewritten using `treq`.
* Migrate test framework from trial to unittest (@lazycrazyowl)

Release 2.3.0
*************

* Deprecate Python 3.6
* Support Python 3.10
* Dependency updates
* MISP Output plugin extension
* add new public keys ECDSAKeys and ed25519 (#1627)
* fix userdb.example (#1619)
* cache url submission to virustotal
* MySQL connector (#1575) - needs new external dependency mysql-connector-python
* Fix mysql string expansion (#1565)
* Rewrite CSIRTG output plugin to use new library version
* Fixed the Slack output to work with the versions 2.x of slackclient
* fix MySQL error handling
* fix tar command
* limit connections to private address ranges
* Update GreyNoise Output Script to Use Community API (#1524)
* Implement getopt-style parsing for uname (#1516)
* Allow SSLv3 connections for wget and curl
* Support for 301 redirects in wget
* Malshare update API (#1472)
* Remove hpfeeds.py infavour of hpfeeds3.py

Release 2.2.0
*************

* Deprecate Python 2.7 and 3.5
* Command substitution with backticks
* Better ``chmod`` command line parsing
* Add ``uniq`` command.
* Enhanced command substitution functionality.
* Fix nc hang
* Rename built-in user ``richard`` to ``phil``, it's used as detection mechanism.
* Binary suppport for ``cat``, ``grep`` and other commands
* Azure Sentinel output plugin

Release 2.1.0
*************

* Deprecate Python 2.7. Still works but removed from testing suite and fixing 2.7 problems will no longer have priority.
* Disable crashreporter
* Updated ELK documentation and output plugin
* ``tee`` command added. Updates to ``cat``, ``dd`` and ``wc``.
* Fixed SSH compression issue with AsyncSSH client
* AbuseIP output plugin.

Release 2.0.1
*************

* 2019-10-31 Fix for exec commands when tty logging is disabled
* 2019-10-31 Fix for print output to stdout for curl/wget
* 2019-10-31 Fix for SQL to store full hostname (don't forget to update the database schema)
* 2019-10-15 Slack link now at https://cowrie.org/slack
* 2019-10-04 Subshell ((echo test)) evaluation now working

Release 2.0.0
*************

* 2019-09-06 Crash reporter is enabled by default and will upload data on crashes to api.cowrie.org. This can be disabled in by setting ``enabled=false`` in ``[output_crashreporter]``
* 2019-09-05 Proxy functionality now active by @sgtpepperpt and GSoC2019
* 2019-06-20 Move `auth_none` and `auth_keyboard_interactive_enabled` to [ssh] config section

Release 1.6.0
*************

* 2019-03-31 New documentation theme
* 2019-03-23 Greynoise output plugin (@mzfr)
* 2019-03-19 direct-tcp forwarding now written to databases (@gborges)
* 2019-03-19 Reverse DNS output plugin (@mzfr)
* 2019-03-17 Shell emulation pipe upgrade (@nunonovais)
* 2019-03-14 Shell emulation environment variables improved (@nunonovais)
* 2019-03-14 SSH crypto parameters now configurable in config file (@msharma)
* 2019-03-13 Disable keyboard-interactive authentication by default with option to enable
* 2019-03-13 Added `wc`, `crontab`, `chpasswd` command (@nunonovais)
* 2019-
* 2019-03-07 Output of `ssh -V` now configurable in cowrie.cfg with ssh_version setting
* 2019-03-07 Multiple timezone support in cowrie.cfg timezone directive. Default timezone is now UTC for both cowrie.log and cowrie.json
* 2019-03-12 Handle multiple password prompt. Option to enable or disable keyboard interactive prompt.

Release 1.5.3
*************

* 2019-01-27 Telnet NAWS negotation removed to stop NMAP cowrie detection
* 2019-01-27 Various fixes for Python2/3 compatibility
* 2019-01-09 Documentation converted to ReStructuredText
* 2018-12-04 Fixes for VT outut plugin to only submit new files

Release 1.5.2
*************

* 2018-11-19 Fix tftp exception and tftp test
* 2018-11-14 Remove `dblog` mechanism and `splunk` legacy output plugin.
* 2018-11-01 Add Python3 support for Splunk output plugin
* 2018-10-23 Improved free command
* 2018-10-20 Improved uname command
* 2018-10-16 Save VT results to JSON log

Release 1.5.1
*************

* 2018-10-13 Fixes VT uploads, tab completion on Python3, Hassh support, setuptools functional. userdb migration
* 2018-09-07 NOTE! data/userdb.txt has moved to etc/userdb.txt and a default config is no longer provided!
* 2018-08-25 Downloads and TTY logs have moved to the var/ directory
* 2018-08-11 SSH keys now stored in var/lib/cowrie
* 2018-07-21 source code has move to the src/ directory. Delete old directories twisted/cowrie with compiled code
* 2018-06-29 txtcmds have been moved to share/cowrie/txtcmds
* 2018-06-28 filesystem config entry has changed. please verify if you have custom entry or pickle file
* 2018-06-23 fingerprint log message now holds KEX attributes and a unique fingerprint for the client
* 2018-04-27 Output plugins now require the mandatory config entry 'enabled'.
* 2018-02-06 cowrie.log now uses same rotation mechanism as cowrie.json. One file per day, rather than the default 1MB per file.
* 2017-12-13 Default umask for logs is now 0007. This means group members can access.
* 2017-10-24 Can store uploaded and downloaded artifacts to S3
* 2017-09-23 First proxy implementation for exec commands only
* 2017-07-03 Cuckoo v2 integration
* 2017-05-16 now combines config files: cowrie.cfg.dist and cowrie.cfg in this order
* 2017-05-09 start.sh and stop.sh have been replace by bin/cowrie start|stop
* 2017-04-27 New syntax "listen_endpoints" for configuring listening IP addresses/portnumbers
* 2017-03-15 SSH Forwarding/SFTP/keys/version config have been moved to [ssh]. Change your config file!
* 2017-02-12 Implemented toggle for SSH forwarding
* 2016-08-22 Merged Telnet support by @obilodeau!
* 2016-08-20 Update your libraries! 'configparser' now required: "pip install configparser"
* 2016-05-06 Load pickle once at startup for improved speed
* 2016-04-28 files in utils/ have been moved to bin/
* 2016-01-19 Support openssh style delayed compression
* 2016-01-13 Correct '.' support and +s and +t bits in ls
* 2016-01-13 Full username/group in SFTP ls
* 2016-01-05 Basic VirusTotal support has been added
* 2016-01-04 No longer crash when client tries ecdsa
* 2015-12-28 Interact port (default 5123) only listens on loopback interface now (127.0.0.1)
* 2015-12-24 Redirect to file (>) now works for most commands and is logged in dl/ directory
* 2015-12-06 UID information is now retrieved from honeyfs/etc/passwd. If you added additional users
             you will need to add these to the passwd file as well
* 2015-12-04 New 'free' command with '-h' and '-m' options
* 2015-12-03 New 'env' command that prints environment variables
* 2015-02-02 Now use honeyfs/etc/passwd and group to get uid/gid info
* 2015-11-29 Size limit now enforced for SFTP uploads
* 2015-11-25 New 'sudo' command added
* 2015-11-19 Queued input during commands is now sent to shell to be executed
             when command is finished
* 2015-11-18 Added SANS DShield output (Thanks @UnrealAkama)
* 2015-11-17 Added ElasticSearch output (Thanks @UnrealAkama)
* 2015-11-17 Standard input is now saved with SHA256 checksum. Duplicate data is not saved
* 2015-11-12 New 'busybox' command added (Thanks @mak)
* 2015-09-26 keyboard-interactive is back as authentication method, after
             Twisted removed support initially
* 2015-07-30 Local syslog output module
* 2015-06-15 Cowrie now has a '-c' startup switch to specify the configuration file
* 2015-06-15 Removed exec_enabled option. This feature is now always enabled
* 2015-06-03 Cowrie now uses twisted plugins and has gained the '-p' commandline option
* 2015-06-01 Cowrie no longer search for config files in /etc and /etc/cowrie
* 2015-04-12 JSON output is now default via 'output' plugin mechanism. Rotates daily
* 2015-04-10 Fix for downloading files via SFTP
* 2015-03-31 Small tweaks on session close, closing session does not close ssh transport
* 2015-03-18 Merged 'AuthRandom' login class by Honigbij
* 2015-02-25 Internals for dblog/ modules changed completely.
             Now accepts structured logging arguments, and uses eventids instead of regex parsing
* 2015-02-20 Removed screen clear/reset on logout
* 2015-02-19 Configuration directives have changed! ssh_addr has become listen_addr and ssh_port has become listen_port. The old keywords are still accepted for backwards compatibility

* default behaviour is changed to disable the exit jail
* sftp support
* exec support
* stdin is saved as a file in dl/ when using exec commands
    to support commands like 'cat >file; ./file'
* allow wget download over non-80 port
* simple JSON logging added
* accept log and deny publickey authentication
* add uname -r, -m flags
* add working sleep command
* enabled ssh diffie-hellman-group-exchange-sha1 algorithm
* add 'bash -c' support (no effect option)
* enable support for && multiple commands
* create uuid to uniquely identify each session
* log and deny direct-tcpip attempts
* add "chattr" command
* support emacs keybindings (c-a, c-b, c-f, c-p, c-n, c-e)
* add "sync" command
* accept, log and deny public key authentication
* add "uname -r" support
* logstash and kibana config files added, based on JSON log
* fix for honeypot detection (pre-auth differences with openssh)
* added verbose logging of client requested key exchange parameters (for client fingerprinting)
* fixes for behavior with non-existent files (cd /test, cat /test/nonexistent, etc)
* fix for ability to ping/ssh non-existent IP address
* always send ssh exit-status 0 on exec and shell
* ls output is now alphabetically sorted
* banner_file is deprecated. honeyfs/etc/issue.net is default
* add 'dir' alias for 'ls'
* add 'help' bash builtin
* add 'users' aliased to 'whoami'
* add 'killall' and 'killall5' aliased to nop
* add 'poweroff' 'halt' and 'reboot' aliases for shutdown
* add environment passing to commands
* added 'which', 'netstat' and 'gcc' from kippo-extra
* logging framework allows for keyword use
