# SPDX-FileCopyrightText: 2026 OrcaRouter
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: OrcaRouter Cyber Inference provider support for Cowrie's LLM backend.
# ABOUTME: Resolves the auth and inference origins, runs the PKCE connect flow,
# ABOUTME: stores the resulting API key, and reads the live model catalog.

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from twisted.logger import Logger

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

_log = Logger()

PROVIDER_ID = "orcarouter"
PROVIDER_LABEL = "OrcaRouter Cyber Inference"
PROVIDER_URL = "https://www.orcarouter.ai/cyber"
CATALOG_URL = "https://www.orcarouter.ai/models?tier=cyber"
KEY_DASHBOARD_URL = "https://www.orcarouter.ai/console/authorized-apps"

# Authentication and inference live on different public origins on purpose.
AUTH_BASE_URL = "https://www.orcarouter.ai"
API_BASE_URL = "https://api.orcarouter.ai/v1"
AUTHORIZE_PATH = "/auth"
EXCHANGE_PATH = "/api/v1/auth/keys"
MODELS_PATH = "/models"
APP_NAME = "Cowrie"

DEFAULT_MODEL = "orcarouter/auto"
# Recommended for security teams (authorized, scoped security work) once the
# workspace is verified for the cyber tier.
CYBER_MODELS = ("orcacyber-ultra-1.0", "orcacyber-zero-1.5")
FALLBACK_MODEL = "orcarouter/fusion"

REQUEST_TIMEOUT = 15.0
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_CATALOG_ITEMS = 500
MAX_ERROR_DETAIL = 200
MAX_MODEL_ID = 200

DEFAULT_CREDENTIALS_FILE = "var/lib/cowrie/orcarouter.json"

CHAT_ENDPOINT_TYPES = frozenset({"openai", "anthropic", "gemini", "openai-response"})
NON_TEXT_ENDPOINT_TYPES = frozenset(
    {"image-generation", "openai-video", "jina-rerank", "embeddings"}
)
CAPABILITIES = ("chat", "embedding", "image", "video", "rerank")
MODALITIES = ("text", "image", "audio", "video")

TERMS_URL = "https://www.orcarouter.ai/terms"
DOCS_URL = "https://www.orcarouter.ai/docs"

# The verified outage fallback lives next to the catalog parser below.
VERIFIED_AT = "2026-10-24"


class OrcaRouterError(Exception):
    """A failure talking to OrcaRouter.

    Messages are safe to log: they never contain the API key, the PKCE
    verifier, or the authorization code.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        retryable: bool = False,
        error_kind: str = "network",
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.error_kind = error_kind


def mask_key(key: str) -> str:
    """Return a display-only form of an API key."""
    if not key:
        return "(none)"
    tail = key[-4:] if len(key) > 8 else ""
    return f"sk-orca-…{tail}" if key.startswith("sk-orca-") else f"…{tail}"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _is_loopback(host: str | None) -> bool:
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


def require_https(url: str, what: str) -> str:
    """Normalise an origin, allowing plain HTTP only for loopback."""
    candidate = url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme == "https" and parsed.hostname:
        return candidate
    if parsed.scheme == "http" and _is_loopback(parsed.hostname):
        return candidate
    if parsed.scheme == "http":
        message = f"{what} must use HTTPS; plain HTTP is only allowed for loopback"
        raise OrcaRouterError(
            message,
            error_kind="config",
        )
    message = f"{what} is not a valid URL"
    raise OrcaRouterError(message, error_kind="config")


def _config_value(option: str) -> str:
    try:
        return CowrieConfig.get("llm", option, fallback="").strip()
    except Exception:  # pragma: no cover - defensive, config is a parser
        return ""


def _env_value(name: str) -> str:
    return os.environ.get(name, "").strip()


def auth_base_url() -> str:
    """Auth origin: explicit override, then shared self-hosted base."""
    explicit = _env_value("ORCA_AUTH_BASE_URL") or _config_value("auth_base_url")
    shared = _env_value("ORCA_BASE_URL") or _config_value("base_url")
    return require_https(
        explicit or shared or AUTH_BASE_URL, "OrcaRouter auth base URL"
    )


def api_base_url() -> str:
    """Inference origin: explicit override, then shared self-hosted base.

    The public default is a constant. It is never derived from the auth origin
    by swapping a hostname or appending ``/v1``: on a self-hosted deployment
    the operator configures both explicitly.
    """
    explicit = _env_value("ORCA_API_BASE_URL") or _config_value("api_base_url")
    shared = _env_value("ORCA_BASE_URL") or _config_value("base_url")
    return require_https(explicit or shared or API_BASE_URL, "OrcaRouter API base URL")


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


@dataclass
class Credential:
    """One user-owned OrcaRouter API key."""

    key: str = field(repr=False)
    scope: str = "api"
    user_id: str = ""
    generation: int = 0
    needs_reauth: bool = False
    source: str = "api_key"
    created_at: str = ""

    @property
    def masked(self) -> str:
        return mask_key(self.key)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "scope": self.scope,
            "user_id": self.user_id,
            "generation": self.generation,
            "needs_reauth": self.needs_reauth,
            "source": self.source,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Credential:
        key = data.get("key")
        if not isinstance(key, str) or not key.startswith("sk-orca-"):
            message = (
                "Stored OrcaRouter credential is not a valid sk-orca- key; "
                "run `cowrie-orcarouter-auth` to reconnect."
            )
            raise OrcaRouterError(
                message,
                error_kind="credential",
            )
        generation = data.get("generation", 0)
        return cls(
            key=key,
            scope=str(data.get("scope", "api")),
            user_id=str(data.get("user_id", "")),
            generation=generation if isinstance(generation, int) else 0,
            needs_reauth=bool(data.get("needs_reauth", False)),
            source=str(data.get("source", "api_key")),
            created_at=str(data.get("created_at", "")),
        )


def credentials_path() -> Path:
    configured = (
        _env_value("COWRIE_ORCAROUTER_CREDENTIALS_FILE")
        or _config_value("credentials_file")
        or DEFAULT_CREDENTIALS_FILE
    )
    return Path(configured)


def catalog_cache_path() -> Path:
    return credentials_path().with_name("orcarouter-catalog.json")


class CredentialStore:
    """Persist the OrcaRouter key in Cowrie's own credential file.

    Cowrie's operator config is hand-edited, so the connect flow writes this
    file instead of rewriting cowrie.cfg. The file is created with mode 0600;
    the key is never logged.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else credentials_path()

    def load(self) -> Credential | None:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            message = (
                f"Cannot read OrcaRouter credentials file {self.path}: {exc.strerror}"
            )
            raise OrcaRouterError(
                message,
                error_kind="credential",
            ) from None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            message = (
                f"OrcaRouter credentials file {self.path} is corrupt; "
                "run `cowrie-orcarouter-auth` to reconnect."
            )
            raise OrcaRouterError(
                message,
                error_kind="credential",
            ) from None
        if not isinstance(data, dict):
            message = (
                f"OrcaRouter credentials file {self.path} is corrupt; "
                "run `cowrie-orcarouter-auth` to reconnect."
            )
            raise OrcaRouterError(
                message,
                error_kind="credential",
            )
        return Credential.from_dict(data)

    def _write(self, credential: Credential) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps(credential.as_dict(), indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".orcarouter-", suffix=".tmp"
        )
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def save(self, credential: Credential) -> Credential:
        """Store a newly obtained key and bump its generation."""
        previous = self.load()
        credential.generation = (previous.generation if previous else 0) + 1
        credential.needs_reauth = False
        credential.created_at = credential.created_at or _now()
        self._write(credential)
        return credential

    def clear(self) -> bool:
        try:
            self.path.unlink()
        except FileNotFoundError:
            return False
        except OSError as exc:
            message = (
                f"Cannot remove OrcaRouter credentials file {self.path}: {exc.strerror}"
            )
            raise OrcaRouterError(
                message,
                error_kind="credential",
            ) from None
        return True

    def mark_needs_reauth(self, generation: int) -> bool:
        """Mark the exact rejected credential generation for reauthentication.

        A late failure from an older generation must not taint a credential
        that was reissued in the meantime, and the stored key is kept until a
        new login succeeds.
        """
        try:
            current = self.load()
        except OrcaRouterError:
            return False
        if current is None or current.generation != generation:
            return False
        if current.needs_reauth:
            return True
        current.needs_reauth = True
        self._write(current)
        return True


# ---------------------------------------------------------------------------
# OAuth 2.0 + PKCE (Flow B: out-of-band code)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PendingLogin:
    """One in-flight authorization attempt."""

    verifier: str = field(repr=False)
    state: str
    challenge: str
    authorize_url: str
    auth_base: str
    app_name: str = APP_NAME
    scope: str = "api"


def begin_login(
    *, app_name: str = APP_NAME, scope: str = "api", auth_base: str | None = None
) -> PendingLogin:
    """Start a PKCE authorization.

    Flow B (out-of-band code) is used because Cowrie runs as a headless
    server daemon, often reached over SSH or in a container, where a
    loopback callback on the operator's machine is not available. The
    verifier is fresh cryptographic randomness per attempt and never leaves
    this process until the exchange.
    """
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = _b64url(secrets.token_bytes(16))
    base = require_https(auth_base or auth_base_url(), "OrcaRouter auth base URL")
    query = urllib.parse.urlencode(
        {
            "callback_url": "oob",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "app_name": app_name,
            "scope": scope,
        }
    )
    return PendingLogin(
        verifier=verifier,
        state=state,
        challenge=challenge,
        authorize_url=f"{base}{AUTHORIZE_PATH}?{query}",
        auth_base=base,
        app_name=app_name,
        scope=scope,
    )


def _oauth_error_message(status: int, body: bytes) -> str:
    known = {
        400: "OrcaRouter rejected the authorization request (HTTP 400)",
        401: "OrcaRouter did not accept the request (HTTP 401)",
        403: "The authorization code is unknown, expired, already used, "
        "or does not match this verifier (HTTP 403)",
        429: "Too many OrcaRouter key issuances for this account right now "
        "(HTTP 429); reuse the stored key or retry later",
    }
    message = known.get(status, f"OrcaRouter returned HTTP {status}")
    detail = ""
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            parts = [
                str(data.get("error", ""))[:80],
                str(data.get("error_description", ""))[:MAX_ERROR_DETAIL],
            ]
            detail = ": ".join(part for part in parts if part)
    except (json.JSONDecodeError, UnicodeDecodeError):
        detail = ""
    return f"{message}: {detail}" if detail else message


def _request_json(
    url: str,
    *,
    method: str,
    payload: dict[str, Any] | None = None,
    api_key: str = "",
    timeout: float = REQUEST_TIMEOUT,
    max_bytes: int = MAX_CATALOG_BYTES,
) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    host = urllib.parse.urlparse(url).hostname or "orcarouter"
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read(min(max_bytes, 64 * 1024))
        message = _oauth_error_message(exc.code, raw)
        message = message
        raise OrcaRouterError(
            message,
            status=exc.code,
            retryable=exc.code in (429, 500, 502, 503, 504),
            error_kind="auth" if exc.code in (401, 403) else "http",
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        message = f"Could not reach {host}: {str(reason)[:MAX_ERROR_DETAIL]}"
        raise OrcaRouterError(
            message,
            retryable=True,
            error_kind="network",
        ) from None

    if len(body) > max_bytes:
        message = f"Response from {host} exceeded {max_bytes} bytes"
        raise OrcaRouterError(
            message,
            error_kind="http",
        )
    if status != 200:
        message = f"OrcaRouter returned HTTP {status}"
        raise OrcaRouterError(message, status=status)
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        message = f"Response from {host} was not valid JSON"
        raise OrcaRouterError(message, error_kind="http") from None
    if not isinstance(parsed, dict):
        message = f"Response from {host} had an unexpected shape"
        raise OrcaRouterError(message, error_kind="http")
    return parsed


def exchange_code(
    pending: PendingLogin,
    code: str,
    *,
    auth_base: str | None = None,
    timeout: float = REQUEST_TIMEOUT,
) -> Credential:
    """Exchange an out-of-band authorization code for a durable API key."""
    base = require_https(auth_base or pending.auth_base, "OrcaRouter auth base URL")
    payload = {
        "code": code.strip(),
        "code_verifier": pending.verifier,
        "code_challenge_method": "S256",
    }
    data = _request_json(
        f"{base}{EXCHANGE_PATH}", method="POST", payload=payload, timeout=timeout
    )
    key = data.get("key")
    if not isinstance(key, str) or not key.startswith("sk-orca-"):
        message = (
            "OrcaRouter did not return a usable API key; run "
            "`cowrie-orcarouter-auth` to retry."
        )
        raise OrcaRouterError(
            message,
            error_kind="auth",
        )
    granted_scope = str(data.get("scope", "api"))
    if granted_scope != "api":
        message = (
            f'OrcaRouter granted scope "{granted_scope}" instead of "api"; '
            "this account or workspace cannot authorize inference keys."
        )
        raise OrcaRouterError(
            message,
            error_kind="auth",
        )
    return Credential(
        key=key,
        scope=granted_scope,
        user_id=str(data.get("user_id", "")),
        source="pkce",
        created_at=_now(),
    )


def store_api_key(key: str) -> Credential:
    """Persist a manually supplied API key through the same credential seam."""
    candidate = key.strip()
    if not candidate.startswith("sk-orca-") or len(candidate) < 12:
        message = "That does not look like an OrcaRouter API key (expected sk-orca-…)"
        raise OrcaRouterError(
            message,
            error_kind="credential",
        )
    credential = Credential(key=candidate, scope="api", source="api_key")
    return CredentialStore().save(credential)


# ---------------------------------------------------------------------------
# Model catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelInfo:
    """One model advertised by the OrcaRouter catalog."""

    id: str
    context_length: int | None = None
    input_modalities: tuple[str, ...] = ()
    endpoint_types: tuple[str, ...] = ()
    reasoning: bool = False
    reasoning_efforts: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "context_length": self.context_length,
            "input_modalities": list(self.input_modalities),
            "endpoint_types": list(self.endpoint_types),
            "reasoning": self.reasoning,
            "reasoning_efforts": list(self.reasoning_efforts),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModelInfo | None:
        model_id = data.get("id")
        if not isinstance(model_id, str) or not model_id.strip():
            return None
        model_id = model_id.strip()
        if len(model_id) > MAX_MODEL_ID or any(ch.isspace() for ch in model_id):
            return None
        context = data.get("context_length")
        if not isinstance(context, int) or context <= 0:
            context = None
        modalities = _string_tuple(data.get("input_modalities"))
        endpoints = _string_tuple(data.get("endpoint_types"))
        efforts = _string_tuple(data.get("reasoning_efforts"))
        return cls(
            id=model_id,
            context_length=context,
            input_modalities=modalities,
            endpoint_types=endpoints,
            reasoning=bool(data.get("reasoning", False)),
            reasoning_efforts=efforts,
        )


# Verified outage fallback. Live discovery is authoritative when it succeeds;
# this seed only keeps a fresh install usable while the catalog is unreachable.
# Metadata stays deliberately conservative: ids are the documented chat models,
# endpoint types are the OpenAI-compatible wire the relay serves, and only the
# reasoning ladder that was verified for GPT-5.5 is listed.
VERIFIED_SEED: tuple[ModelInfo, ...] = (
    ModelInfo(
        id="openai/gpt-5.5",
        endpoint_types=("openai",),
        reasoning=True,
        reasoning_efforts=("low", "medium", "high", "xhigh"),
    ),
    ModelInfo(id="anthropic/claude-opus-4.8", endpoint_types=("openai",)),
    ModelInfo(id="google/gemini-3.5-flash", endpoint_types=("openai",)),
    ModelInfo(id="deepseek/deepseek-v4-pro", endpoint_types=("openai",)),
    ModelInfo(id="orcarouter/auto", endpoint_types=("openai",)),
)


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        item.strip()
        for item in value
        if isinstance(item, str) and 0 < len(item.strip()) <= 64
    )[:16]


def parse_catalog_item(item: object) -> ModelInfo | None:
    """Accept only well-formed catalog entries; anything else is dropped."""
    if not isinstance(item, dict):
        return None
    model_id = item.get("id")
    if not isinstance(model_id, str):
        return None

    architecture = item.get("architecture")
    modalities: Sequence[str] = ()
    if isinstance(architecture, dict):
        modalities = _string_tuple(architecture.get("input_modalities"))
        if not modalities:
            # An architecture block without declared modalities is opaque:
            # treat it as text-only rather than assuming more than it says.
            modalities = ("text",)

    endpoints = _string_tuple(item.get("supported_endpoint_types"))
    efforts = _string_tuple(item.get("reasoning_efforts"))
    reasoning = bool(item.get("reasoning", False))
    context = item.get("context_length")
    if not isinstance(context, int) or context <= 0:
        context = None

    return ModelInfo.from_dict(
        {
            "id": model_id,
            "context_length": context,
            "input_modalities": list(modalities),
            "endpoint_types": list(endpoints),
            "reasoning": reasoning,
            "reasoning_efforts": list(efforts),
        }
    )


def _chat_ok(model: ModelInfo) -> bool:
    if NON_TEXT_ENDPOINT_TYPES.intersection(model.endpoint_types):
        return False
    return bool(CHAT_ENDPOINT_TYPES.intersection(model.endpoint_types))


def _matches_capability(model: ModelInfo, capability: str) -> bool:
    endpoints = set(model.endpoint_types)
    if capability == "chat":
        return _chat_ok(model)
    if capability == "embedding":
        return "embeddings" in endpoints
    if capability == "image":
        return "image-generation" in endpoints
    if capability == "video":
        return "openai-video" in endpoints
    if capability == "rerank":
        return "jina-rerank" in endpoints
    message = f"unknown capability {capability!r}"
    raise ValueError(message)


def filter_models(
    models: Iterable[ModelInfo], capability: str, modality: str | None = None
) -> tuple[ModelInfo, ...]:
    """Capability- and modality-aware options for a model selector.

    Missing metadata never widens a list: a chat model without a declared
    input modality is excluded from a multimodal list, and a model whose
    endpoint types do not include a text chat wire type is excluded from chat.
    """
    if capability not in CAPABILITIES:
        message = f"unknown capability {capability!r}"
        raise ValueError(message)
    if modality is not None and modality not in MODALITIES:
        message = f"unknown modality {modality!r}"
        raise ValueError(message)
    selected = []
    for model in models:
        if not _matches_capability(model, capability):
            continue
        if modality is not None and capability == "chat":
            if modality not in model.input_modalities:
                continue
        selected.append(model)
    return tuple(selected)


@dataclass(frozen=True)
class CatalogResult:
    """Outcome of one catalog read, including degraded states."""

    models: tuple[ModelInfo, ...]
    source: str  # live | cache | seed
    degraded: bool = False
    error: str = ""
    error_kind: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "degraded": self.degraded,
            "error": self.error,
            "error_kind": self.error_kind,
            "models": [model.as_dict() for model in self.models],
        }


def _catalog_cache_key(capability: str, modality: str | None) -> str:
    return f"{capability}:{modality or ''}"


def _load_cached_models(capability: str, modality: str | None) -> tuple[ModelInfo, ...]:
    try:
        raw = json.loads(catalog_cache_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    entries = raw.get("entries") if isinstance(raw, dict) else None
    if not isinstance(entries, dict):
        return ()
    items = entries.get(_catalog_cache_key(capability, modality))
    if not isinstance(items, list):
        return ()
    parsed = [ModelInfo.from_dict(item) for item in items if isinstance(item, dict)]
    return tuple(model for model in parsed if model is not None)[:MAX_CATALOG_ITEMS]


def _save_catalog_cache(
    capability: str, modality: str | None, models: Sequence[ModelInfo]
) -> None:
    path = catalog_cache_path()
    entries: dict[str, Any] = {}
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(existing, dict) and isinstance(existing.get("entries"), dict):
            entries = existing["entries"]
    except (OSError, json.JSONDecodeError):
        entries = {}
    entries[_catalog_cache_key(capability, modality)] = [
        model.as_dict() for model in models
    ]
    payload = json.dumps(
        {"saved_at": _now(), "verified_at": VERIFIED_AT, "entries": entries},
        indent=2,
        sort_keys=True,
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=".orcarouter-catalog-", suffix=".tmp"
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        os.replace(tmp_name, path)
    except OSError:
        # A cache is an optimisation; failing to write it must not break
        # model discovery.
        _log.warn("Could not write OrcaRouter model cache to {path}", path=str(path))


def seed_models(
    capability: str = "chat", modality: str | None = None
) -> tuple[ModelInfo, ...]:
    return filter_models(VERIFIED_SEED, capability, modality)


def fetch_catalog(
    api_key: str,
    *,
    api_base: str | None = None,
    capability: str = "chat",
    modality: str | None = None,
    timeout: float = REQUEST_TIMEOUT,
    use_cache: bool = True,
) -> CatalogResult:
    """Read the live OrcaRouter catalog, bounded and filtered.

    A successful read is authoritative: the verified seed is never mixed
    into it. On failure the last known-good catalog or the seed is returned
    with ``degraded=True`` so the caller can say so.
    """
    base = require_https(api_base or api_base_url(), "OrcaRouter API base URL")
    if not api_key:
        return _degraded_catalog(
            capability,
            modality,
            "No OrcaRouter API key is configured; run `cowrie-orcarouter-auth`.",
            error_kind="auth",
            use_cache=use_cache,
        )

    query = {"capability": capability}
    url = f"{base}{MODELS_PATH}?{urllib.parse.urlencode(query)}"
    try:
        payload = _request_json(url, method="GET", api_key=api_key, timeout=timeout)
    except OrcaRouterError as exc:
        return _degraded_catalog(
            capability, modality, str(exc), exc.error_kind, use_cache=use_cache
        )

    items = payload.get("data")
    if not isinstance(items, list):
        return _degraded_catalog(
            capability,
            modality,
            "OrcaRouter model catalog had an unexpected shape",
            "http",
            use_cache=use_cache,
        )

    parsed: list[ModelInfo] = []
    for item in items[:MAX_CATALOG_ITEMS]:
        model = parse_catalog_item(item)
        if model is not None:
            parsed.append(model)
    models = filter_models(parsed, capability, modality)
    if models:
        _save_catalog_cache(capability, modality, models)
    return CatalogResult(models=models, source="live")


def _degraded_catalog(
    capability: str,
    modality: str | None,
    error: str,
    error_kind: str,
    *,
    use_cache: bool,
) -> CatalogResult:
    if use_cache:
        cached = _load_cached_models(capability, modality)
        if cached:
            return CatalogResult(
                models=cached,
                source="cache",
                degraded=True,
                error=error,
                error_kind=error_kind,
            )
    return CatalogResult(
        models=seed_models(capability, modality),
        source="seed",
        degraded=True,
        error=error,
        error_kind=error_kind,
    )
