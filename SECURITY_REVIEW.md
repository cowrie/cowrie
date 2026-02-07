# Cowrie Security, Maintainability, and Documentation Review

**Date:** 2026-02-07
**Scope:** Full codebase review of Cowrie SSH/Telnet honeypot

---

## 1. Security Findings

### 1.1 CRITICAL: Unsafe Pickle Deserialization

Pickle deserialization allows arbitrary code execution if the loaded file is
tampered with. Three locations use `pickle.load()` without any restrictions:

- **`src/cowrie/shell/fs.py:115-122`** -- Loads the fake filesystem from a
  pickle file. If an attacker can replace `fs.pickle`, they gain code execution
  on the honeypot host.
- **`src/cowrie/scripts/fsctl.py:117`** -- The filesystem editor tool also
  loads pickle without validation.
- **`src/cowrie/output/abuseipdb.py:81`** -- Loads a state dump from disk via
  `pickle.load(f)`.

**Recommendation:** Migrate away from pickle. The filesystem could use a JSON
or MessagePack format with an explicit schema. At minimum, use
`RestrictedUnpickler` to limit what classes can be instantiated. For the
AbuseIPDB state, switch to JSON serialization.

---

### 1.2 CRITICAL: Backend Credentials Logged in Plaintext

In `src/cowrie/ssh_proxy/client_transport.py:89`:

```python
log.msg(f"Will auth with backend: {username}/{password}")
```

This logs the backend SSH proxy credentials (from config keys `proxy.backend_user`
and `proxy.backend_pass`) in plaintext to the Cowrie log. Anyone with log access
can read the backend password.

**Recommendation:** Remove this log line entirely or replace with a redacted
version that does not include the password.

---

### 1.3 HIGH: SSH Private Keys Written Without Restricted Permissions

In `src/cowrie/ssh/keys.py`, the three key-generation functions
(`getRSAKeys` at line 61, `getECDSAKeys` at line 93, `geted25519Keys` at
line 125) write private key files using the default umask:

```python
with open(privateKeyFile, "w+b") as f:
    f.write(privateKeyString)
```

No explicit `chmod(0o600)` is applied. Depending on the user's umask, the
private key file could be world-readable.

**Recommendation:** After writing private key files, explicitly call
`os.chmod(path, 0o600)`.

---

### 1.4 HIGH: Hardcoded Fallback Token and Environment Variable Leakage

In `src/cowrie/output/csirtg.py:11-16`:

```python
token = CowrieConfig.get("output_csirtg", "token", fallback="a1b2c3d4")
os.environ["CSIRTG_TOKEN"] = token
```

Issues:
- The fallback value `"a1b2c3d4"` is a guessable placeholder. Although the
  code exits if it matches, setting a real-looking default is risky if the
  check is ever removed.
- The token is placed into `os.environ`, making it visible to all child
  processes, core dumps, and `/proc/<pid>/environ`.

**Recommendation:** Avoid environment variable injection for secrets. Pass the
token directly to the SDK if possible.

---

### 1.5 HIGH: Backend SSH Host Key Verification Disabled

In `src/cowrie/ssh_proxy/client_transport.py:60-61`:

```python
def verifyHostKey(self, hostKey, fingerprint):
    return defer.succeed(True)
```

The proxy unconditionally accepts any host key from the backend SSH server.
This makes the proxy-to-backend connection vulnerable to man-in-the-middle
attacks.

**Recommendation:** Implement host key pinning or verification against a
known-hosts file for the backend server.

---

### 1.6 MEDIUM: Default Bind Address is 0.0.0.0

In `src/cowrie/core/utils.py:116`:

```python
listen_addr = "0.0.0.0"
```

When no `listen_addr` is configured, the honeypot binds to all interfaces.
For a honeypot this may be intentional, but the NAT listeners in
`src/backend_pool/nat.py:129,132` also hardcode `interface="0.0.0.0"`,
exposing internal pool NAT ports to all interfaces.

**Recommendation:** The backend pool NAT listeners should bind to `127.0.0.1`
by default rather than all interfaces, since they are internal services.

---

### 1.7 MEDIUM: Log File Permissions Too Open

In `src/cowrie/output/jsonlog.py:57-58`:

```python
cowrie.python.logfile.CowrieDailyLogFile(base, dirs, defaultMode=0o664)
```

Log files are created world-readable (`0o664`). These logs contain attacker
session data, passwords, and potentially sensitive deployment information.

**Recommendation:** Use `0o640` or `0o600` for log files.

---

### 1.8 LOW: `os.system("clear")` in fsctl

In `src/cowrie/scripts/fsctl.py:777`:

```python
os.system("clear")
```

This uses the deprecated `os.system()` which invokes a shell. While the
argument is hardcoded, best practice is to use `subprocess.run(["clear"])`.

---

### 1.9 LOW: Dependencies Pin Exact Versions

All dependencies in `requirements.txt` and `pyproject.toml` are pinned to
exact versions (e.g., `cryptography==46.0.4`). This is good for
reproducibility but means security patches require a manual version bump.
The project does use Dependabot, which mitigates this.

**Current dependency versions appear up-to-date as of the review date.**

---

## 2. Maintainability Findings

### 2.1 `requires-python` Specifier is Misleading

In `pyproject.toml:14`:

```toml
requires-python = ">=2.7, !=3.0.*, !=3.1.*, ... !=3.9.*, <4"
```

This technically allows Python 2.7 installation, but the code uses Python 3.10+
features (`from __future__ import annotations`, `match` statements, type union
syntax). The README correctly states Python 3.10+. The CI tests only Python
3.10-3.15.

**Recommendation:** Change to `requires-python = ">=3.10"`.

---

### 2.2 Code Duplication in `ssh/keys.py`

The three functions `getRSAKeys()`, `getECDSAKeys()`, and `geted25519Keys()`
follow an identical pattern (check config, load from file, or generate and
write). The only differences are the config key names and the key generation
call. This could be consolidated into a single parameterized function.

---

### 2.3 50+ Unresolved TODO/FIXME Comments

The codebase contains over 50 TODO/FIXME/HACK comments across modules
including:

- `ssh_proxy/client_transport.py` -- TODOs about account creation
- `shell/fs.py` -- FIXMEs about filesystem operations
- `shell/command.py` -- FIXME about naive command parsing
- `backend_pool/pool_service.py` -- 4 TODOs about VM handling
- `telnet/userauth.py` -- 2 TODOs and 1 FIXME
- `core/utils.py:134` -- FIXME about `addService`
- And many more across commands and output plugins

**Recommendation:** Triage these into GitHub issues and either resolve them or
remove obsolete ones.

---

### 2.4 Inconsistent Naming Convention

- `geted25519Keys()` in `ssh/keys.py:100` uses lowercase `ed25519` while the
  other functions use camelCase (`getRSAKeys`, `getECDSAKeys`).
- Mix of snake_case and camelCase throughout the codebase (inherited from
  Twisted conventions vs. Python PEP 8).

---

### 2.5 Test Coverage Gaps

The project has 24 test files covering primarily command implementations. Notable
gaps include:

- No tests for output plugins (37 plugins, 0 tests except VirusTotal)
- No tests for the LLM backend module
- No integration tests for the SSH/Telnet protocol handlers
- No tests for the backend pool or NAT modules
- No tests for `core/auth.py` credential checking

---

### 2.6 Strong Points

- **Comprehensive CI/CD:** Tests across Python 3.10-3.15 + PyPy, with linting,
  type checking (mypy, pyright, pyre), and docs building.
- **Multiple type checkers:** mypy, pyright, pyre, and pytype configured.
- **Modern tooling:** ruff for linting, pre-commit hooks, Dependabot.
- **Clean separation of concerns:** Core, shell, SSH, Telnet, output, and proxy
  modules are well-separated.
- **Docker:** Multi-stage build with distroless base image is a good security
  practice.

---

## 3. Documentation Findings

### 3.1 Outdated Path References (Post-v2.7.0 Breaking Change)

Version 2.7.0 moved scripts from `bin/` to setuptools entry points and renamed
`share/cowrie/` to `src/cowrie/data/`. Several docs still reference the old paths:

| File | Outdated Reference | Should Be |
|------|--------------------|-----------|
| `docs/FAQ.rst:29` | `bin/fsctl share/cowrie/fs.pickle` | `fsctl src/cowrie/data/fs.pickle` |
| `docs/FAQ.rst:51` | `fsctl share/cowrie/fs.pickle` | `fsctl src/cowrie/data/fs.pickle` |
| `docs/OUTPUT.rst:175` | `bin/playlog` | `playlog` |
| `docs/BACKEND_POOL.rst` | `share/cowrie/pool_configs` | `src/cowrie/data/pool_configs` |

---

### 3.2 Backend Pool References Outdated VM Images

`docs/BACKEND_POOL.rst:14-41` references Ubuntu 18.04 and OpenWRT 18.06.4 images
from 2019 hosted on Google Drive. Ubuntu 18.04 reached end-of-life in April 2023.

**Recommendation:** Update to current LTS images (Ubuntu 24.04) or add a
disclaimer about the age of these images.

---

### 3.3 Output Plugins Largely Undocumented

Of 37 output plugins, only ~8 have dedicated documentation (via subdirectories
in `docs/`): datadog, ELK, graylog, prometheus, sentinel, splunk, SQL, and
VirusTotal.

The remaining 29 plugins (including abuseipdb, discord, slack, telegram, MISP,
MongoDB, Redis, S3, GreyNoise, etc.) have no documentation beyond inline
comments and configuration examples in `cowrie.cfg.dist`.

---

### 3.4 Missing Security Hardening Guide

There is no documentation covering:
- Recommended file permissions for the Cowrie installation
- Network isolation recommendations for the honeypot host
- Log security and access control
- Credential management best practices
- Firewall rules for backend pool VMs

---

### 3.5 `cowrie.log.closed` Event Documentation Outdated

In `docs/OUTPUT.rst:175`, the `ttylog` attribute description reads:

> filename of session log that can be replayed with `bin/playlog`

The `bin/` prefix is obsolete since v2.7.0. The command is now simply `playlog`.

---

### 3.6 No Custom Command Development Guide

New contributors wanting to add emulated commands have no guide to follow.
The `src/cowrie/shell/README.md` is a single line. A guide explaining the
`HoneyPotCommand` base class, command registration, and testing patterns would
improve contributor onboarding.

---

## 4. Summary of Recommendations

### Immediate (Security-Critical)
1. Remove plaintext credential logging in `ssh_proxy/client_transport.py:89`
2. Add restricted unpickler or migrate `fs.pickle` away from pickle format
3. Set `0o600` permissions on generated SSH private key files
4. Implement backend SSH host key verification

### Short-Term (Documentation)
5. Fix all outdated `bin/` and `share/cowrie/` path references in docs
6. Update Backend Pool docs with current VM images
7. Simplify `requires-python` to `">=3.10"`

### Medium-Term (Maintainability)
8. Document remaining 29 output plugins
9. Triage and resolve or remove 50+ TODO/FIXME comments
10. Add tests for output plugins, auth module, and protocol handlers
11. Add a security hardening guide to the documentation
12. Refactor duplicated key generation code in `ssh/keys.py`
