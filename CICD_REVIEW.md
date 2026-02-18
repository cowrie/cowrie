# CI/CD Pipeline Review

## Pipeline Structure Overview

The repository has 5 workflows: `tox.yml` (testing), `pypi.yml` (production release),
`test-pypi.yml` (staging release), `docker.yml` (container build/publish), and
`weekly-release.yml` (automated patch bumps). Plus Dependabot for dependency updates.

The overall structure is solid. There is a clear progression from testing to staging to
release to containers, and the pipeline makes good use of modern GHA features (OIDC
trusted publishing, multi-platform Docker builds, Cosign signing).

---

## Structural / Pipeline-Level Recommendations

### 1. Tests don't gate releases — the biggest gap

The `pypi.yml` and `docker.yml` workflows trigger independently on tag pushes. There is
no dependency on `tox.yml` passing. A tag push could publish a broken package to PyPI and
Docker Hub simultaneously if tests are failing.

**Recommendation:** Make the release workflows depend on tests passing. Options:
- Use `workflow_run` to trigger `pypi.yml` and `docker.yml` only after `tox.yml` succeeds
  on the tag.
- Or consolidate into a single release workflow with a `test` job that gates the
  `publish-pypi` and `publish-docker` jobs via `needs:`.

### 2. `weekly-release.yml` creates tags without running tests first

The weekly release job creates a GitHub release (and therefore a tag) purely based on
commit count since the last tag. It does not verify that `main` is in a passing state.
This tag immediately triggers `pypi.yml` and `docker.yml`, potentially publishing broken
artifacts.

**Recommendation:** Add a test job in the weekly release workflow that runs `tox` before
creating the release, or use the GitHub API to check that the latest commit's status
checks are passing before proceeding.

### 3. Heavy duplication between `pypi.yml` and `test-pypi.yml`

These two files are nearly identical — the only differences are the trigger (tag vs.
`main`), the environment name, and the `repository-url` parameter. This is a maintenance
burden: any fix must be applied in both places.

**Recommendation:** Consolidate into a single reusable workflow (or a single file with
two jobs) parameterized by the target registry.

### 4. Docker image is built twice per push

In `docker.yml`, the build job runs `docker/build-push-action` twice per platform — once
with `load: true` for testing, and again with `push: true` for publishing. This doubles
build time.

**Recommendation:** Use the Docker build cache with the GitHub Actions cache backend so
the second build is essentially a no-op. The Buildx action supports
`cache-from: type=gha` and `cache-to: type=gha,mode=max`.

### 5. No lint/type-check visibility in CI

The `tox.yml` workflow runs the default tox envlist driven by `tox-gh-actions` mapping.
The `lint`, `typing`, and `docs` environments only run for specific Python versions
(`3.13` and `3.14` respectively) and aren't visible as separate checks.

**Recommendation:** Create a dedicated `lint.yml` workflow (or a separate job in
`tox.yml`) that always runs `tox -e lint,typing,docs` on a fixed Python version.

---

## Per-Workflow Detailed Recommendations

### `tox.yml`

- **`on: push` triggers on ALL branches.** Every push to every branch runs the full
  10-version matrix. Scope this to `main` plus PR events, or exclude `dependabot/**`
  branches.
- **`workflow_dispatch` inputs are unused.** The `logLevel` and `tags` inputs are defined
  but never referenced. Either wire them up or remove them.
- **Full `.[dev]` install is heavy.** Every matrix job installs the full dev dependencies
  including Sphinx, mypy, pylint, etc., even though most jobs only run unit tests.
  Consider a lighter install for test-only runs.
- **No pip caching.** Adding `actions/setup-python`'s built-in pip caching
  (`cache: 'pip'`) would speed up the matrix significantly.

### `pypi.yml`

- **Pinned action hash without version comment.** `pypa/gh-action-pypi-publish@ed0c53...`
  is pinned by hash (good for security), but there is no comment indicating which version
  it corresponds to.
- **`verify-metadata: false`.** This disables metadata verification. If there was a
  specific reason, it should be documented. Otherwise, leave it enabled.
- **`sleep 60s` is fragile.** It assumes 60 seconds is enough for PyPI propagation.
  Consider a retry loop with `pip install --retries` or a poll-based approach.
- **The "Download and test" step** runs `twistd cowrie` without any timeout. If cowrie
  starts and doesn't exit, the job hangs. Run it with `--help` or `--version` instead.
- **`workflow_dispatch` inputs are unused**, same as tox.yml.

### `test-pypi.yml`

- Same issues as `pypi.yml` above (duplication).
- **Runs on every push to `main`.** Every merged PR publishes to test-pypi. If two PRs
  merge in quick succession, the second could fail if the version hasn't incremented
  (test-pypi doesn't allow re-uploading the same version).

### `docker.yml`

- **Container test is minimal.** `docker run -d --rm cowrie:test` starts the container
  detached and never checks if it actually came up healthy. Add a health check with
  timeout, then inspect the exit code or logs.
- **`v*` tag pattern is too broad.** It matches any tag starting with `v`, including
  `v2-beta` or `version-note`. Use the same specific pattern as `pypi.yml`:
  `v[0-9]+.[0-9]+.[0-9]+`.
- **Cosign version is pinned old.** `sigstore/cosign-installer@v4.0.0` with
  `cosign-release: 'v2.4.1'`.
- **`COSIGN_EXPERIMENTAL: 1` is deprecated** in newer Cosign versions. Keyless signing is
  now the default. Remove this env var.
- **No Docker layer caching.** Adding `cache-from` / `cache-to` with the GHA cache
  backend would significantly reduce build times.

### `weekly-release.yml`

- **Only increments patch version.** If a breaking change or new feature lands, the weekly
  release still bumps the patch. Consider conventional commits or label-based versioning.
- **No protection against concurrent runs.** If manually triggered while a scheduled run
  is in progress, both could try to create the same tag. Add a `concurrency` group.
- **Release title is just the version number.** Consider a more descriptive title like
  "Cowrie v1.2.4 (automated weekly release)".

---

## Dockerfile Recommendations

- **Hardcoded Python 3.11 in compileall** (line 101): `compileall` targets
  `/usr/lib/python3.11` but the distroless base image may ship a different version.
- **No `.dockerignore`.** `COPY . ${COWRIE_HOME}/cowrie-git` copies the entire repo
  including `.git/`, test files, docs, etc.
- **`EXPOSE` after `CMD`.** Convention is to place `EXPOSE` before `ENTRYPOINT`/`CMD`.

---

## Pre-commit Configuration

- **Hooks are very stale.** Black is pinned at `22.12.0`, isort at `5.11.4`, pyupgrade at
  `v3.3.1`, pre-commit-hooks at `v4.4.0` — all from late 2022 / early 2023. The project
  uses `ruff` in tox. Consider switching pre-commit to `ruff` (which replaces black,
  isort, pyupgrade, and yesqa).
- **pyupgrade `--py38-plus`** doesn't match the project's minimum Python 3.10. Should be
  `--py310-plus`.

---

## Summary of Priorities

| Priority | Recommendation |
|----------|---------------|
| **High** | Gate releases on passing tests (pypi.yml, docker.yml, weekly-release.yml all publish without test verification) |
| **High** | Consolidate pypi.yml / test-pypi.yml to eliminate duplication |
| **Medium** | Add Docker build caching to avoid double-builds |
| **Medium** | Add pip caching to tox.yml matrix |
| **Medium** | Improve Docker container health check in CI |
| **Medium** | Scope tox.yml push triggers to avoid unnecessary matrix runs |
| **Medium** | Modernize or remove stale pre-commit config |
| **Low** | Fix hardcoded Python version in Dockerfile compileall |
| **Low** | Add `.dockerignore` |
| **Low** | Clean up unused workflow_dispatch inputs |
| **Low** | Update Cosign, remove deprecated COSIGN_EXPERIMENTAL |
