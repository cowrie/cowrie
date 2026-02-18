# CI/CD & DevOps Pipeline Review

## Executive Summary

Cowrie has a functional CI/CD pipeline with 5 GitHub Actions workflows, Dependabot,
Docker multi-platform builds, OIDC-based PyPI publishing, and Cosign image signing.
These are strong foundations.

However, a review against established DevOps practices reveals several structural gaps:
the pipeline lacks quality gates between stages, the build/packaging configuration has
accumulated contradictions, the linting toolchain is fractured across three systems,
dependency management follows conflicting strategies, and there is no security scanning.

This document covers: pipeline architecture, testing, linting, dependency management,
releasing, Docker, and general DevOps hygiene.

---

## 1. Pipeline Architecture

### 1.1 No quality gates between stages (Critical)

The most important DevOps principle is that artifacts flow through a pipeline where each
stage gates the next. Cowrie's pipeline violates this:

- **Tag push** triggers `pypi.yml`, `docker.yml`, and `tox.yml` independently and in
  parallel. A broken tag publishes broken artifacts to PyPI and Docker Hub before tests
  finish — or even if tests fail.
- **`weekly-release.yml`** creates tags based purely on commit count, with no check that
  `main` is green. This tag then triggers the ungated publishing workflows.
- **`test-pypi.yml`** publishes on every push to `main`, again without waiting for
  `tox.yml` to pass.

In a well-structured pipeline, the flow should be:

```
test → build → publish-staging → publish-production
```

Each stage should depend on the previous one succeeding.

**Recommendation:** Consolidate into a release workflow where `publish-pypi` and
`publish-docker` jobs have `needs: [test]`. For the weekly release, either embed a test
job or use the GitHub API to verify the commit status before tagging. For `test-pypi.yml`,
use `workflow_run` to trigger only after `tox.yml` succeeds on `main`.

### 1.2 No concurrency controls

None of the workflows define `concurrency` groups. This means:

- Two pushes in quick succession run two full matrix builds simultaneously, wasting
  resources and potentially causing race conditions in publishing.
- A manual `workflow_dispatch` during a scheduled `weekly-release` could create duplicate
  tags.
- Two PRs merging quickly can both try to publish to test-pypi with the same version.

**Recommendation:** Add `concurrency` groups to all workflows. For publishing workflows,
use `cancel-in-progress: false` (let the first one finish). For test workflows, use
`cancel-in-progress: true` (supersede stale runs).

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true  # for test workflows
```

### 1.3 Heavy duplication between `pypi.yml` and `test-pypi.yml`

These files are nearly identical — differing only in trigger, environment name, and
`repository-url`. Any fix must be applied twice.

**Recommendation:** Extract a reusable workflow
(`.github/workflows/pypi-publish-reusable.yml`) parameterized by environment and
repository URL. Both `pypi.yml` and `test-pypi.yml` become thin callers.

### 1.4 `tox.yml` triggers on every push to every branch

The `on: push` trigger has no branch filter. Every push to every branch — including
Dependabot branches that already have associated PRs — runs the full 10-version Python
matrix. This is wasteful and inflates CI minutes.

**Recommendation:** Scope push triggers to `main` only. PRs already have their own
trigger. Dependabot PRs will naturally run via the `pull_request` trigger.

```yaml
on:
  push:
    branches: [main]
  pull_request:
```

---

## 2. Testing

### 2.1 Test runner is minimal

Tests use `python -m unittest discover src --verbose`. This works but lacks:

- **Coverage reporting** — there is a `[testenv:coverage-report]` in tox.ini and a
  `[coverage:run]` config, but the main `[testenv]` does not run coverage. The coverage
  env is not in the gh-actions mapping. Coverage is effectively dead config.
- **No test result reporting in CI** — test results are only visible in raw log output.
  There is no JUnit XML output, no GitHub Actions test summary, no annotations on
  failures.
- **No test parallelization** — 20 test files run sequentially in each matrix job.

**Recommendation:**
- Wire up coverage in CI: `coverage run -m unittest discover src` in `[testenv]`, then
  upload with `codecov/codecov-action` or similar.
- Add `--junit-xml` output (requires `unittest-xml-reporting` or switching to `pytest`)
  and use `dorny/test-reporter` or `mikepenz/action-junit-report` for GitHub annotations.
- Consider switching to `pytest` — it is the de facto standard, supports parallel
  execution via `pytest-xdist`, has native JUnit XML output, and is a much better fit for
  modern Python projects.

### 2.2 Tests are co-located with source code

Tests live in `src/cowrie/test/` rather than a top-level `tests/` directory. This means
tests are packaged and distributed with the library. While this is a valid pattern for
some projects, it increases package size and is unconventional for applications (vs.
libraries).

**Note:** This is a stylistic choice and not necessarily wrong, but it means the Docker
image and PyPI package both contain test code.

### 2.3 No integration or smoke tests

All 20 test files are unit tests. There is no integration test that:

- Starts cowrie and connects via SSH/Telnet
- Verifies the Docker image actually accepts connections
- Tests output plugins against real (or mocked) backends

The Docker workflow's "test" step (`docker run -d --rm cowrie:test`) is a smoke test in
name only — it starts the container detached and never checks if it came up or accepts
connections.

**Recommendation:** Add a basic smoke test that starts cowrie and attempts an SSH
connection (e.g., `ssh -o StrictHostKeyChecking=no ... exit` with a timeout). This
catches packaging errors, missing dependencies, and configuration issues that unit tests
miss.

---

## 3. Linting & Code Quality

### 3.1 Three competing linting systems

The project currently uses three different linting/formatting systems:

| System | Tools | Where it runs |
|--------|-------|---------------|
| **Pre-commit** | black, isort, pyupgrade, yesqa | Local dev (manual) |
| **Tox lint env** | ruff, yamllint, pyright, pylint | CI (Python 3.10 only) |
| **Tox typing env** | mypy, mypyc, pyre, pyright | CI (Python 3.10 only) |

Problems:
- **Black vs. Ruff:** Pre-commit runs `black` for formatting, but tox runs `ruff` for
  linting. Ruff includes a formatter (`ruff format`) that replaces black. Running both is
  redundant and can produce conflicts.
- **isort vs. Ruff:** Pre-commit runs `isort`, but ruff's `I` rules handle import
  sorting. The ruff config doesn't enable `I` rules (line 175 of pyproject.toml), creating
  a gap.
- **pyupgrade `--py38-plus`:** Pre-commit's pyupgrade targets Python 3.8, but the
  project's minimum is 3.10. This means pyupgrade is leaving Python 3.9 and 3.10 upgrades
  on the table.
- **Four type checkers:** The typing env runs mypy, mypyc, pyre, AND pyright. Three of
  these are prefixed with `-` (continue on error). Running four type checkers is unusual
  and expensive. Most projects pick one (mypy or pyright) and commit to it.
- **Pre-commit hooks are 2+ years stale:** Black `22.12.0`, isort `5.11.4`, pyupgrade
  `v3.3.1`, pre-commit-hooks `v4.4.0` — all from late 2022 / early 2023.

**Recommendation:** Consolidate on ruff. It replaces black, isort, pyupgrade, yesqa, and
many pyflakes/pylint rules in a single, fast tool. Update `.pre-commit-config.yaml` to
use `ruff` (both `ruff check --fix` and `ruff format`), and remove black/isort/pyupgrade
/yesqa hooks. Pick one type checker (mypy or pyright) and drop the others.

### 3.2 Lint results are not enforced

In the tox lint environment, three of four commands are prefixed with `-` (continue on
error):

```
commands =
    ruff check {toxinidir}/src          # enforced (fails the build)
    - yamllint {toxinidir}              # soft failure
    - pyright                           # soft failure
    - pylint {toxinidir}/src            # soft failure
```

This means only ruff failures actually block CI. yamllint, pyright, and pylint failures
are silently ignored.

**Recommendation:** Either enforce these checks (remove the `-` prefix) or remove them
from CI. Soft-failing checks create a false sense of security and accumulate ignored
warnings over time.

### 3.3 No linting in CI as a separate check

Lint, docs, and typing are bundled into the Python 3.10 tox matrix entry via the
`gh-actions` mapping. They don't appear as separate GitHub status checks. A reviewer
cannot tell at a glance whether linting passed or failed — they would need to expand the
"3.10" matrix entry and read the logs.

**Recommendation:** Create a separate `lint` job (or workflow) that runs independently and
reports as its own GitHub check.

### 3.4 No hadolint in CI

The Makefile has `hadolint docker/Dockerfile` in the `lint` target, but CI does not run
hadolint. Dockerfile linting only happens if a developer remembers to run `make lint`
locally.

**Recommendation:** Add hadolint to the CI lint job. There is a
`hadolint/hadolint-action` for GitHub Actions.

---

## 4. Dependency Management

### 4.1 Three sources of dependency truth

Dependencies are declared in three places:

| Location | Format | Used by |
|----------|--------|---------|
| `pyproject.toml` `[project].dependencies` | Exact pins (`==`) | `pip install cowrie`, `pip install -e .` |
| `requirements.txt` | Exact pins (`==`) | Docker build, tox `deps` |
| `requirements-output.txt` | Exact pins (`==`) | Docker build (output backends) |

These are not in sync. `requirements.txt` contains `urllib3==2.6.3` which is absent from
`pyproject.toml`. `pyproject.toml` does not include `urllib3` at all — it is a transitive
dependency of `requests`.

**Recommendation:** Pick one source of truth:
- For an **application** (which cowrie is): Use `requirements.txt` as a lockfile
  generated from `pyproject.toml`. Tools like `pip-compile` (from `pip-tools`) or `uv`
  can generate exact pins including transitive dependencies from loose constraints in
  `pyproject.toml`.
- Change `pyproject.toml` dependencies to use `>=` constraints (lower bounds) instead of
  `==` pins. Exact pins in `pyproject.toml` make the PyPI package fragile — if any
  dependency releases a new version, users cannot install cowrie alongside other packages
  that need the newer version.

### 4.2 Exact version pins in `pyproject.toml` are an anti-pattern for published packages

Every dependency in `pyproject.toml` uses `==` pins:

```toml
dependencies = [
    "attrs==25.4.0",
    "bcrypt==5.0.0",
    "cryptography==46.0.5",
    ...
]
```

This is appropriate for a lockfile but problematic for a published package. When a user
runs `pip install cowrie`, pip must resolve these exact versions. If any other package in
their environment needs a different version of `cryptography` or `attrs`, installation
fails with a dependency conflict.

The standard practice is:
- `pyproject.toml`: Use compatible release (`~=`) or minimum (`>=`) constraints
- `requirements.txt` (or `uv.lock`/`poetry.lock`): Use exact pins for reproducible builds

### 4.3 `requires-python` is stale

```toml
requires-python = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, !=3.6.*, !=3.7.*, !=3.8.*, !=3.9.*, <4"
```

This says the project supports Python 2.7 and Python 3.10+. The CHANGELOG explicitly
states Python 3.9 was dropped in 2.7.0 and Python 2.7 was dropped in 2.2.0. The correct
value is simply `>=3.10, <4`.

### 4.4 `setup.py` is stale and contradictory

`setup.py` still exists alongside `pyproject.toml`:

```python
setup(
    packages=["cowrie", "twisted"],
    include_package_data=True,
    package_dir={"": "src"},
    package_data={"": ["*.md"]},
    setup_requires=["click"],
)
```

Problems:
- `setup_requires=["click"]` — click is not a build dependency and is never used
- `packages=["cowrie", "twisted"]` — this claims to package `twisted`, which is incorrect
  and conflicts with `pyproject.toml`'s `setuptools.packages.find`
- The dangling `refresh_plugin_cache()` function is never called
- `setup.py` is only needed for editable installs on older pip versions. Modern pip
  handles editable installs with just `pyproject.toml`.

**Recommendation:** Delete `setup.py` entirely if all developers use pip >= 21.3.

### 4.5 Dev dependency versions are pinned in `pyproject.toml`

```toml
dev = [
    "build==1.4.0",
    "coverage==7.10.7",
    "mypy==1.19.1",
    "ruff==0.15.0",
    ...
]
```

Pinning dev dependencies in `pyproject.toml` optional extras is unusual. These are
developer tools, not user-facing dependencies. The standard approach is to put dev tool
pins in a `requirements-dev.txt` (lockfile) and keep `pyproject.toml` optional deps
unpinned or with minimum versions.

### 4.6 Dependabot covers the right ecosystems

Dependabot is configured for pip, GitHub Actions, and Docker — this is good coverage.
However, it will create PRs to update `requirements.txt` but won't know to also update
the corresponding `pyproject.toml` pin, further exacerbating the multi-source-of-truth
problem.

---

## 5. Releasing

### 5.1 Weekly automated releases with no semantic meaning

`weekly-release.yml` increments the patch version every Monday if there are new commits.
This conflates "time passed" with "release-worthy changes." A week of typo fixes gets
the same release treatment as a week of security patches or breaking changes.

The patch version always increments, even for breaking changes. Users who depend on
semver cannot trust the version number.

**Recommendation:** Consider one of:
- **Conventional Commits** + a tool like `python-semantic-release` to determine
  major/minor/patch from commit messages
- **Manual releases** with the weekly job as a reminder (open a draft release or issue)
  rather than auto-publishing
- At minimum, add a label-based override (e.g., `release:minor`, `release:major`) that
  the weekly job checks

### 5.2 No changelog automation

`CHANGELOG.rst` is manually maintained. The weekly release uses `--generate-notes` which
produces a raw commit list, but the actual changelog file is not updated. Over time, the
changelog will drift further from reality.

**Recommendation:** Either automate changelog generation from conventional commits, or
have the release workflow update `CHANGELOG.rst` as part of the release PR.

### 5.3 `pypi.yml` smoke test can hang

The post-publish verification step runs:

```yaml
- name: Download and test package
  run: |
    python -m pip install cowrie
    twistd cowrie
```

`twistd cowrie` starts a long-running daemon. Without a timeout, this step hangs until
the GHA job-level timeout (6 hours by default).

**Recommendation:** Use `twistd --help` or `cowrie --version` for a quick import check.
If you want a real smoke test, use `timeout 10 twistd -n cowrie` and accept exit code
124 (timeout) as success.

### 5.4 Sleep-based propagation wait

```yaml
- name: Sleep for publishing
  run: sleep 60s
```

This is a common anti-pattern. 60 seconds might not be enough for a slow PyPI mirror, or
it might waste 50 seconds when propagation is fast.

**Recommendation:** Replace with a retry loop:

```bash
for i in 1 2 3 4 5; do
  pip install cowrie==$VERSION && break
  sleep 15
done
```

---

## 6. Docker

### 6.1 Container test is meaningless

```yaml
- name: Test
  run: docker run -d --rm cowrie:test
```

This starts the container detached and immediately returns success. It does not check
whether the process is healthy, whether it started listening on ports, or whether it
crashed immediately after starting.

**Recommendation:**

```yaml
- name: Test
  run: |
    docker run -d --name cowrie-test -p 2222:2222 cowrie:test
    sleep 5
    docker exec cowrie-test python3 -c "import cowrie"
    # Optionally: check if port 2222 is listening
    docker logs cowrie-test
    docker stop cowrie-test
```

### 6.2 `v*` tag pattern is too broad

`docker.yml` triggers on `tags: [v*]` but `pypi.yml` uses the stricter
`v[0-9]+.[0-9]+.[0-9]+`. A tag like `v2-rc1` or `v2024-experiment` would trigger a
Docker build but not a PyPI publish, leading to version inconsistency.

**Recommendation:** Use the same tag pattern across all workflows.

### 6.3 No Docker build caching in CI

Each CI build starts from scratch. The Buildx action supports GitHub Actions cache:

```yaml
- uses: docker/build-push-action@v6
  with:
    cache-from: type=gha
    cache-to: type=gha,mode=max
```

This can reduce build times dramatically for incremental changes.

### 6.4 `.dockerignore` is minimal but exists

The `.dockerignore` excludes `.direnv`, `.tox`, `.git`, `.github`, `.eggs`. It does not
exclude `docs/`, `*.md`, `*.rst`, `CHANGELOG.rst`, `Makefile`, `.pre-commit-config.yaml`,
`*.pyc`, `__pycache__`, or test files. These all get copied into the build context and
(for files outside `src/`) into the image.

**Recommendation:** Expand `.dockerignore` to exclude everything not needed at runtime.

### 6.5 Hardcoded Python version in Dockerfile

```dockerfile
RUN [ "python3", "-m", "compileall", "-q", "/cowrie/cowrie-git/src", "/cowrie/cowrie-env/", "/usr/lib/python3.11"]
```

This hardcodes `/usr/lib/python3.11`. If the distroless base image updates to Python
3.12, this path silently does nothing (compileall of a non-existent directory is not an
error).

**Recommendation:** Use a dynamic path:

```dockerfile
RUN [ "python3", "-c", "import sys, compileall; compileall.compile_path(quiet=1)" ]
```

Or determine the path at build time from the Python version.

### 6.6 Makefile `docker-build` has a broken shell expansion

```makefile
docker-build: docker/Dockerfile
	SETUPTOOLS_SCM_PRETEND_VERSION_FOR_COWRIE=$(python -m setuptools_scm ...)
	-$(DOCKER) buildx create --append --name cowrie-builder
	$(DOCKER) buildx build ...
```

Make runs each line in a separate shell. The environment variable set on line 1 is lost
before line 3 executes. The Docker build never receives the version override.

**Recommendation:** Either chain commands with `&&` in a single line, use `.ONESHELL:`,
or use Make's `export` directive.

### 6.7 Cosign configuration is outdated

- `sigstore/cosign-installer@v4.0.0` with `cosign-release: 'v2.4.1'` — both are outdated
- `COSIGN_EXPERIMENTAL: 1` is deprecated; keyless signing is the default in current
  Cosign versions

**Recommendation:** Update to latest cosign-installer and remove the deprecated env var.

---

## 7. Security & DevOps Hygiene

### 7.1 No SAST/security scanning

The project has no:

- **CodeQL** or **Semgrep** for static application security testing
- **Trivy** or **Grype** for container image vulnerability scanning
- **pip-audit** or **safety** for Python dependency vulnerability scanning
- **SECURITY.md** security policy file

For a **security tool** (honeypot), the absence of security scanning in CI is a
significant gap. Attackers target honeypots specifically, and a vulnerability in cowrie
itself could compromise the host.

**Recommendation:**
- Add CodeQL (free for public repos, one-click setup via GitHub)
- Add `pip-audit` to the lint job to catch known-vulnerable dependencies
- Add Trivy scanning of the Docker image
- Create a `SECURITY.md` with a vulnerability disclosure policy

### 7.2 No CODEOWNERS

There is no `.github/CODEOWNERS` file. For a project with external contributors, this
means PRs can be merged without review from maintainers if branch protection is not
configured.

### 7.3 `workflow_dispatch` inputs are unused everywhere

`tox.yml`, `pypi.yml`, `test-pypi.yml`, and `docker.yml` all define `logLevel` and `tags`
inputs that are never referenced. This is dead config that confuses contributors.

**Recommendation:** Remove the unused inputs, or wire them up.

### 7.4 Pinned action versions are inconsistent

Some actions use tag versions (`actions/checkout@v6`, `docker/setup-buildx-action@v3`),
while others use commit hashes (`pypa/gh-action-pypi-publish@ed0c53...`). Hash pinning is
more secure (tags can be force-pushed), but the inconsistency means some actions are
protected against supply chain attacks and others are not.

**Recommendation:** Pin all third-party actions by hash with a version comment. Let
Dependabot manage the updates. First-party GitHub actions (`actions/*`) are lower risk
and can stay on major version tags.

---

## 8. Summary: Prioritized Recommendations

### Critical (fix immediately)

| # | Issue | Impact |
|---|-------|--------|
| 1 | Releases are not gated on tests passing | Broken code can be published to PyPI and Docker Hub |
| 2 | `requires-python` includes Python 2.7 | Users on Python 2.7 or 3.9 will try to install and fail |
| 3 | No security scanning for a security tool | Honeypot vulnerabilities directly compromise hosts |

### High (fix soon)

| # | Issue | Impact |
|---|-------|--------|
| 4 | `==` pins in `pyproject.toml` for published package | Dependency conflicts for users |
| 5 | Three sources of dependency truth (out of sync) | Inconsistent behavior across install methods |
| 6 | Stale `setup.py` with incorrect metadata | Confusing for contributors, potential build issues |
| 7 | Consolidate `pypi.yml` / `test-pypi.yml` duplication | Maintenance burden, divergence risk |
| 8 | `pypi.yml` smoke test can hang the job | Wasted CI minutes, false "still running" status |

### Medium (improve quality)

| # | Issue | Impact |
|---|-------|--------|
| 9 | Three competing lint/format systems | Contributor confusion, potential conflicts |
| 10 | Lint results are soft-fail (not enforced) | False sense of code quality |
| 11 | No test coverage tracking | No visibility into untested code |
| 12 | `tox.yml` runs on all branches | Wasted CI minutes |
| 13 | No Docker build caching | Slow CI, wasted compute |
| 14 | Docker container test is meaningless | False confidence in image health |
| 15 | Weekly release has no semantic versioning | Versions do not communicate change severity |
| 16 | Add `concurrency` groups | Race conditions in publishing |

### Low (cleanup)

| # | Issue | Impact |
|---|-------|--------|
| 17 | Pre-commit hooks 2+ years stale | Not catching modern Python patterns |
| 18 | Hardcoded Python 3.11 in Dockerfile compileall | Silent no-op on base image update |
| 19 | Expand `.dockerignore` | Smaller build context, smaller image |
| 20 | Unused `workflow_dispatch` inputs everywhere | Dead config clutter |
| 21 | Makefile docker-build shell expansion is broken | Local Docker builds don't get version info |
| 22 | Outdated Cosign, deprecated `COSIGN_EXPERIMENTAL` | Deprecation warnings, missing fixes |
| 23 | No CODEOWNERS file | PRs may lack required reviews |
| 24 | Inconsistent action version pinning strategy | Uneven supply chain protection |
