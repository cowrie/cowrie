# SPDX-FileCopyrightText: 2026 OrcaRouter
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the OrcaRouter Cyber Inference provider: both credential
# ABOUTME: adapters, PKCE exchange, origins, catalog filtering and 401 recovery.

from __future__ import annotations

import base64
import builtins
import getpass
import hashlib
import json
import os
import stat
import tempfile
import threading
import unittest
import webbrowser
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from typing import Any, Self
from unittest.mock import patch

from twisted.internet import defer
from twisted.web.client import Agent, ProxyAgent

from cowrie.llm import llm as llm_module
from cowrie.llm import orcarouter
from cowrie.scripts import orcarouter_auth, orcarouter_models
from cowrie.test.configoverride import override_option

FAKE_KEY = "sk-orca-test-0000000000000001"
FAKE_KEY_TWO = "sk-orca-test-0000000000000002"

CATALOG_FIXTURE = [
    {
        "id": "text/model",
        "supported_endpoint_types": ["openai"],
        "architecture": {"input_modalities": ["text"]},
        "context_length": 128000,
    },
    {
        "id": "vision/model",
        "supported_endpoint_types": ["openai"],
        "architecture": {"input_modalities": ["text", "image"]},
    },
    {"id": "anthropic/model", "supported_endpoint_types": ["anthropic"]},
    {"id": "gemini/model", "supported_endpoint_types": ["gemini"]},
    {"id": "responses/model", "supported_endpoint_types": ["openai-response"]},
    {
        "id": "embed/model",
        "supported_endpoint_types": ["embeddings"],
        "architecture": {"input_modalities": ["text"]},
    },
    {"id": "image/model", "supported_endpoint_types": ["image-generation"]},
    {"id": "video/model", "supported_endpoint_types": ["openai-video"]},
    {"id": "rerank/model", "supported_endpoint_types": ["jina-rerank"]},
    {"id": "no-endpoint-types/model", "architecture": {"input_modalities": ["text"]}},
]


class FakeOrcaServer:
    """A tiny HTTP server standing in for the auth and catalog origins."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}
        self.requests: list[dict[str, Any]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _record(self) -> bytes:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                server.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body,
                    }
                )
                return body

            def _respond(self) -> None:
                self._record()
                status, payload = server.routes.get(
                    (self.command, self.path), (404, {"error": "not_found"})
                )
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = _respond
            do_POST = _respond

            def log_message(self, *args: Any) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host = str(self.httpd.server_address[0])
        port = int(self.httpd.server_address[1])
        return f"http://{host}:{port}"

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class TempCredentialCase(unittest.TestCase):
    """Give every test its own credential file under a temp directory."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.credentials = Path(self.tmp.name) / "orcarouter.json"
        override_option(self, "llm", "credentials_file", str(self.credentials))

    def make_client(self) -> llm_module.LLMClient:
        return llm_module.LLMClient()

    def _deferred_result(self, deferred: defer.Deferred) -> Any:
        self.assertTrue(deferred.called, "deferred did not resolve synchronously")
        return deferred.result


class ProviderPresetTests(TempCredentialCase):
    def test_orcarouter_is_a_named_first_class_provider(self) -> None:
        override_option(self, "llm", "provider", "orcarouter")
        override_option(self, "llm", "api_key", FAKE_KEY)
        client = self.make_client()

        self.assertEqual(client.provider, "orcarouter")
        self.assertEqual(client.provider_label, "OrcaRouter Cyber Inference")
        self.assertEqual(client.host, "https://api.orcarouter.ai")
        self.assertEqual(client.path, "/v1/chat/completions")
        self.assertEqual(client.model, "orcarouter/auto")
        self.assertFalse(client.is_anthropic)

    def test_default_orcarouter_model_is_auto(self) -> None:
        self.assertEqual(orcarouter.DEFAULT_MODEL, "orcarouter/auto")
        self.assertIn("orcacyber-ultra-1.0", orcarouter.CYBER_MODELS)
        self.assertEqual(orcarouter.FALLBACK_MODEL, "orcarouter/fusion")

    def test_unset_provider_keeps_legacy_behaviour(self) -> None:
        override_option(self, "llm", "api_key", FAKE_KEY)
        client = self.make_client()

        self.assertEqual(client.provider, "custom")
        self.assertEqual(client.host, "https://api.openai.com")
        self.assertEqual(client.path, "/v1/chat/completions")
        self.assertEqual(client.model, "gpt-4o-mini")

    def test_explicit_host_still_overrides_the_preset(self) -> None:
        override_option(self, "llm", "provider", "orcarouter")
        override_option(self, "llm", "api_key", FAKE_KEY)
        override_option(self, "llm", "host", "https://relay.example.net")
        client = self.make_client()

        self.assertEqual(client.host, "https://relay.example.net")

    def test_bearer_header_uses_the_resolved_key(self) -> None:
        override_option(self, "llm", "provider", "orcarouter")
        override_option(self, "llm", "api_key", FAKE_KEY)
        client = self.make_client()

        self.assertEqual(
            client._build_headers().getRawHeaders(b"Authorization"),
            [f"Bearer {FAKE_KEY}".encode()],
        )


class ProxyPolicyTests(TempCredentialCase):
    def test_orcarouter_host_can_bypass_a_foreign_proxy(self) -> None:
        override_option(self, "llm", "provider", "orcarouter")
        override_option(self, "llm", "api_key", FAKE_KEY)
        env = {
            "https_proxy": "http://127.0.0.1:3128",
            "no_proxy": "localhost,api.orcarouter.ai",
        }
        with patch.dict(os.environ, env, clear=False):
            client = self.make_client()

        self.assertIsInstance(client.agent, Agent)
        self.assertNotIsInstance(client.agent, ProxyAgent)

    def test_proxy_is_still_used_for_a_host_it_covers(self) -> None:
        override_option(self, "llm", "provider", "orcarouter")
        override_option(self, "llm", "api_key", FAKE_KEY)
        env = {
            "https_proxy": "http://127.0.0.1:3128",
            "no_proxy": ".internal.example",
        }
        with patch.dict(os.environ, env, clear=False):
            client = self.make_client()

        self.assertIsInstance(client.agent, ProxyAgent)


class CredentialStoreTests(TempCredentialCase):
    def test_save_load_masks_and_clear(self) -> None:
        store = orcarouter.CredentialStore()
        saved = store.save(
            orcarouter.Credential(key=FAKE_KEY, scope="api", user_id="42")
        )

        self.assertEqual(saved.generation, 1)
        loaded = store.load()
        assert loaded is not None
        self.assertEqual(loaded.key, FAKE_KEY)
        self.assertNotIn(FAKE_KEY, repr(loaded))
        self.assertNotIn(FAKE_KEY, loaded.masked)
        self.assertEqual(loaded.masked, "sk-orca-…0001")

        mode = stat.S_IMODE(self.credentials.stat().st_mode)
        self.assertEqual(mode, 0o600)

        self.assertTrue(store.clear())
        self.assertIsNone(store.load())
        self.assertFalse(store.clear())

    def test_generation_increments_on_each_login(self) -> None:
        store = orcarouter.CredentialStore()
        store.save(orcarouter.Credential(key=FAKE_KEY))
        second = store.save(orcarouter.Credential(key=FAKE_KEY_TWO))

        self.assertEqual(second.generation, 2)

    def test_corrupt_file_is_terminal_and_does_not_echo_contents(self) -> None:
        self.credentials.write_text("{not json", encoding="utf-8")
        with self.assertRaises(orcarouter.OrcaRouterError) as caught:
            orcarouter.CredentialStore().load()

        self.assertEqual(caught.exception.error_kind, "credential")
        self.assertIn("cowrie-orcarouter-auth", str(caught.exception))

    def test_file_with_bad_key_shape_is_rejected(self) -> None:
        self.credentials.write_text(json.dumps({"key": "not-a-key"}), encoding="utf-8")
        with self.assertRaises(orcarouter.OrcaRouterError):
            orcarouter.CredentialStore().load()


class ApiKeyAdapterTests(TempCredentialCase):
    def test_api_key_adapter_persists_and_is_used_by_the_client(self) -> None:
        credential = orcarouter.store_api_key(FAKE_KEY)
        self.assertEqual(credential.source, "api_key")

        override_option(self, "llm", "provider", "orcarouter")
        client = self.make_client()

        self.assertEqual(client.api_key, FAKE_KEY)
        self.assertEqual(client._key_source, "credentials_file")

    def test_malformed_key_is_refused(self) -> None:
        with self.assertRaises(orcarouter.OrcaRouterError):
            orcarouter.store_api_key("sk-wrong-prefix-0000")


class PkceTests(TempCredentialCase):
    def test_verifier_and_state_are_fresh_and_random(self) -> None:
        first = orcarouter.begin_login()
        second = orcarouter.begin_login()

        self.assertNotEqual(first.verifier, second.verifier)
        self.assertNotEqual(first.state, second.state)
        self.assertGreaterEqual(len(first.verifier), 43)

    def test_challenge_is_unpadded_s256_base64url(self) -> None:
        pending = orcarouter.begin_login()
        expected = _b64url(hashlib.sha256(pending.verifier.encode()).digest())

        self.assertEqual(pending.challenge, expected)
        self.assertNotIn("=", pending.challenge)
        self.assertNotEqual(pending.challenge, pending.verifier)

    def test_authorize_url_targets_the_auth_origin_only(self) -> None:
        pending = orcarouter.begin_login()
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(
            pending.authorize_url
        )
        params = dict(
            __import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(parsed.query)
        )

        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "www.orcarouter.ai")
        self.assertEqual(parsed.path, "/auth")
        self.assertEqual(params["callback_url"], "oob")
        self.assertEqual(params["code_challenge_method"], "S256")
        self.assertEqual(params["code_challenge"], pending.challenge)
        self.assertEqual(params["state"], pending.state)
        self.assertEqual(params["app_name"], "Cowrie")
        self.assertEqual(params["scope"], "api")
        self.assertNotIn(pending.verifier, pending.authorize_url)

    def test_exchange_uses_the_auth_path_and_sends_the_verifier_in_the_body(
        self,
    ) -> None:
        with FakeOrcaServer() as server:
            server.routes[("POST", "/api/v1/auth/keys")] = (
                200,
                {"key": FAKE_KEY, "user_id": "7", "scope": "api"},
            )
            pending = orcarouter.begin_login(auth_base=server.url)

            credential = orcarouter.exchange_code(pending, "one-time-code")

            self.assertEqual(credential.key, FAKE_KEY)
            self.assertEqual(credential.scope, "api")
            self.assertEqual(credential.source, "pkce")

            request = server.requests[-1]
            self.assertEqual(request["path"], "/api/v1/auth/keys")
            self.assertNotIn("one-time-code", request["path"])
            self.assertNotIn(pending.verifier, request["path"])
            body = json.loads(request["body"])
            self.assertEqual(body["code"], "one-time-code")
            self.assertEqual(body["code_verifier"], pending.verifier)
            self.assertEqual(body["code_challenge_method"], "S256")

    def test_exchange_never_hits_the_inference_origin(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("POST", "/api/v1/auth/keys")] = (
                200,
                {"key": FAKE_KEY, "scope": "api"},
            )
            pending = orcarouter.begin_login(auth_base=server.url)
            orcarouter.exchange_code(pending, "code")

        self.assertTrue(all(r["path"] != "/v1/auth/keys" for r in server.requests))
        self.assertEqual(orcarouter.EXCHANGE_PATH, "/api/v1/auth/keys")
        self.assertFalse(orcarouter.EXCHANGE_PATH.startswith("/v1/"))

    def test_scope_downgrade_is_reported_not_assumed_away(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("POST", "/api/v1/auth/keys")] = (
                200,
                {"key": FAKE_KEY, "scope": "connector"},
            )
            pending = orcarouter.begin_login(auth_base=server.url)

            with self.assertRaises(orcarouter.OrcaRouterError) as caught:
                orcarouter.exchange_code(pending, "code")

        self.assertIn("connector", str(caught.exception))

    def test_denied_code_reports_cleanly(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("POST", "/api/v1/auth/keys")] = (
                403,
                {"error": "access_denied", "error_description": "user declined"},
            )
            pending = orcarouter.begin_login(auth_base=server.url)

            with self.assertRaises(orcarouter.OrcaRouterError) as caught:
                orcarouter.exchange_code(pending, "code")

        self.assertIn("access_denied", str(caught.exception))
        self.assertNotIn(pending.verifier, str(caught.exception))

    def test_400_403_429_and_network_errors_are_distinguished(self) -> None:
        cases = {400: "400", 403: "403", 429: "429"}
        for status, needle in cases.items():
            with FakeOrcaServer() as server:
                server.routes[("POST", "/api/v1/auth/keys")] = (status, {"error": "x"})
                pending = orcarouter.begin_login(auth_base=server.url)
                with self.assertRaises(orcarouter.OrcaRouterError) as caught:
                    orcarouter.exchange_code(pending, "code", timeout=5)
            self.assertIn(needle, str(caught.exception))
            self.assertNotIn(pending.verifier, str(caught.exception))

        with FakeOrcaServer() as server:
            url = server.url
        pending = orcarouter.begin_login(auth_base=url)
        with self.assertRaises(orcarouter.OrcaRouterError) as caught:
            orcarouter.exchange_code(pending, "code", timeout=2)
        self.assertEqual(caught.exception.error_kind, "network")
        self.assertNotIn(pending.verifier, str(caught.exception))

    def test_two_adapters_produce_the_same_downstream_credential(self) -> None:
        """Downstream never knows which adapter produced the key."""
        with FakeOrcaServer() as server:
            server.routes[("POST", "/api/v1/auth/keys")] = (
                200,
                {"key": FAKE_KEY, "scope": "api", "user_id": "7"},
            )
            pending = orcarouter.begin_login(auth_base=server.url)
            pkce_credential = orcarouter.exchange_code(pending, "code")

        store = orcarouter.CredentialStore()
        store.save(pkce_credential)
        override_option(self, "llm", "provider", "orcarouter")
        from_pkce = self.make_client()
        pkce_header = from_pkce._build_headers().getRawHeaders(b"Authorization")

        orcarouter.store_api_key(FAKE_KEY)
        from_api_key = self.make_client()
        api_header = from_api_key._build_headers().getRawHeaders(b"Authorization")

        self.assertEqual(from_pkce.model, from_api_key.model)
        self.assertEqual(from_pkce.host, from_api_key.host)
        self.assertEqual(pkce_header, api_header)


class OriginPolicyTests(TempCredentialCase):
    def test_default_origins(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            for name in ("ORCA_BASE_URL", "ORCA_AUTH_BASE_URL", "ORCA_API_BASE_URL"):
                os.environ.pop(name, None)
            self.assertEqual(orcarouter.auth_base_url(), "https://www.orcarouter.ai")
            self.assertEqual(orcarouter.api_base_url(), "https://api.orcarouter.ai/v1")

    def test_shared_and_explicit_overrides(self) -> None:
        base = {"ORCA_BASE_URL": "https://selfhosted.example.net"}
        with patch.dict(os.environ, base, clear=False):
            self.assertEqual(
                orcarouter.auth_base_url(), "https://selfhosted.example.net"
            )
            self.assertEqual(
                orcarouter.api_base_url(), "https://selfhosted.example.net"
            )

        explicit = {
            "ORCA_BASE_URL": "https://selfhosted.example.net",
            "ORCA_AUTH_BASE_URL": "https://login.example.net",
            "ORCA_API_BASE_URL": "https://relay.example.net/v9",
        }
        with patch.dict(os.environ, explicit, clear=False):
            self.assertEqual(orcarouter.auth_base_url(), "https://login.example.net")
            self.assertEqual(orcarouter.api_base_url(), "https://relay.example.net/v9")

    def test_plain_http_is_rejected_off_loopback(self) -> None:
        with patch.dict(os.environ, {"ORCA_AUTH_BASE_URL": "http://evil.example.net"}):
            with self.assertRaises(orcarouter.OrcaRouterError):
                orcarouter.auth_base_url()
        with patch.dict(os.environ, {"ORCA_API_BASE_URL": "http://127.0.0.1:9999/v1"}):
            self.assertEqual(orcarouter.api_base_url(), "http://127.0.0.1:9999/v1")


class CatalogParsingTests(unittest.TestCase):
    def test_chat_filter_excludes_non_text_and_untyped_models(self) -> None:
        models = [
            m for item in CATALOG_FIXTURE if (m := orcarouter.parse_catalog_item(item))
        ]

        chat = orcarouter.filter_models(models, "chat")

        self.assertEqual(
            [m.id for m in chat],
            [
                "text/model",
                "vision/model",
                "anthropic/model",
                "gemini/model",
                "responses/model",
            ],
        )

    def test_multimodal_filter_requires_declared_modality(self) -> None:
        models = [
            m for item in CATALOG_FIXTURE if (m := orcarouter.parse_catalog_item(item))
        ]

        vision = orcarouter.filter_models(models, "chat", "image")

        self.assertEqual([m.id for m in vision], ["vision/model"])

    def test_other_capabilities_are_strict(self) -> None:
        models = [
            m for item in CATALOG_FIXTURE if (m := orcarouter.parse_catalog_item(item))
        ]

        self.assertEqual(
            [m.id for m in orcarouter.filter_models(models, "embedding")],
            ["embed/model"],
        )
        self.assertEqual(
            [m.id for m in orcarouter.filter_models(models, "image")], ["image/model"]
        )
        self.assertEqual(
            [m.id for m in orcarouter.filter_models(models, "video")], ["video/model"]
        )
        self.assertEqual(
            [m.id for m in orcarouter.filter_models(models, "rerank")],
            ["rerank/model"],
        )

    def test_missing_architecture_metadata_fails_closed(self) -> None:
        model = orcarouter.parse_catalog_item(
            {"id": "opaque/model", "supported_endpoint_types": ["openai"]}
        )
        assert model is not None
        self.assertEqual(model.input_modalities, ())
        self.assertEqual(orcarouter.filter_models([model], "chat", "image"), ())

    def test_malformed_items_are_dropped(self) -> None:
        self.assertIsNone(orcarouter.parse_catalog_item("nope"))
        self.assertIsNone(orcarouter.parse_catalog_item({"id": ""}))
        self.assertIsNone(orcarouter.parse_catalog_item({"id": "has space"}))
        self.assertIsNone(orcarouter.parse_catalog_item({"id": 5}))


class LiveCatalogTests(TempCredentialCase):
    def test_live_catalog_is_used_verbatim_without_seed(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("GET", "/v1/models?capability=chat")] = (
                200,
                {"data": [CATALOG_FIXTURE[0], CATALOG_FIXTURE[1]]},
            )
            result = orcarouter.fetch_catalog(
                FAKE_KEY, api_base=server.url + "/v1", capability="chat"
            )

            self.assertFalse(result.degraded)
            self.assertEqual(result.source, "live")
            self.assertEqual(
                [m.id for m in result.models], ["text/model", "vision/model"]
            )
            header = server.requests[-1]["headers"].get("Authorization", "")
            self.assertEqual(header, f"Bearer {FAKE_KEY}")

    def test_image_modality_narrows_the_same_live_catalog(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("GET", "/v1/models?capability=chat")] = (
                200,
                {"data": CATALOG_FIXTURE},
            )
            result = orcarouter.fetch_catalog(
                FAKE_KEY,
                api_base=server.url + "/v1",
                capability="chat",
                modality="image",
            )

        self.assertEqual([m.id for m in result.models], ["vision/model"])

    def test_outage_falls_back_to_verified_seed_marked_degraded(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("GET", "/v1/models?capability=chat")] = (
                503,
                {"error": "unavailable"},
            )
            result = orcarouter.fetch_catalog(
                FAKE_KEY, api_base=server.url + "/v1", use_cache=False, timeout=5
            )

        self.assertTrue(result.degraded)
        self.assertEqual(result.source, "seed")
        self.assertIn("orcarouter/auto", [m.id for m in result.models])
        gpt = next(m for m in result.models if m.id == "openai/gpt-5.5")
        self.assertEqual(gpt.reasoning_efforts, ("low", "medium", "high", "xhigh"))

    def test_last_known_good_catalog_is_reused_before_the_seed(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("GET", "/v1/models?capability=chat")] = (
                200,
                {"data": [CATALOG_FIXTURE[1]]},
            )
            first = orcarouter.fetch_catalog(
                FAKE_KEY, api_base=server.url + "/v1", capability="chat"
            )
        self.assertEqual(first.source, "live")

        with FakeOrcaServer() as server:
            server.routes[("GET", "/v1/models?capability=chat")] = (
                500,
                {"error": "boom"},
            )
            cached = orcarouter.fetch_catalog(
                FAKE_KEY, api_base=server.url + "/v1", capability="chat", timeout=5
            )
            no_cache = orcarouter.fetch_catalog(
                FAKE_KEY,
                api_base=server.url + "/v1",
                capability="chat",
                timeout=5,
                use_cache=False,
            )

        self.assertEqual(cached.source, "cache")
        self.assertTrue(cached.degraded)
        self.assertEqual([m.id for m in cached.models], ["vision/model"])
        self.assertEqual(no_cache.source, "seed")

    def test_auth_failure_is_reported_as_such(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("GET", "/v1/models?capability=chat")] = (
                401,
                {"error": "invalid_api_key"},
            )
            result = orcarouter.fetch_catalog(
                FAKE_KEY, api_base=server.url + "/v1", use_cache=False, timeout=5
            )

        self.assertTrue(result.degraded)
        self.assertEqual(result.error_kind, "auth")
        self.assertNotIn(FAKE_KEY, result.error)

    def test_empty_live_catalog_is_an_empty_state_not_a_seed(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("GET", "/v1/models?capability=chat")] = (200, {"data": []})
            result = orcarouter.fetch_catalog(
                FAKE_KEY, api_base=server.url + "/v1", capability="chat"
            )

        self.assertEqual(result.models, ())
        self.assertFalse(result.degraded)
        self.assertEqual(result.source, "live")

    def test_catalog_reads_are_bounded(self) -> None:
        many = [
            {"id": f"model/{i}", "supported_endpoint_types": ["openai"]}
            for i in range(600)
        ]
        with FakeOrcaServer() as server:
            server.routes[("GET", "/v1/models?capability=chat")] = (200, {"data": many})
            result = orcarouter.fetch_catalog(
                FAKE_KEY, api_base=server.url + "/v1", capability="chat"
            )

        self.assertEqual(len(result.models), orcarouter.MAX_CATALOG_ITEMS)


class ModelOptionsCliTests(TempCredentialCase):
    def _catalog(self, ids: list[str]) -> orcarouter.CatalogResult:
        models = tuple(
            orcarouter.ModelInfo(id=model_id, endpoint_types=("openai",))
            for model_id in ids
        )
        return orcarouter.CatalogResult(models=models, source="live")

    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = orcarouter_models.main(argv)
        return status, out.getvalue(), err.getvalue()

    def test_options_come_from_the_configured_catalog(self) -> None:
        override_option(self, "llm", "provider", "orcarouter")
        override_option(self, "llm", "api_key", FAKE_KEY)
        override_option(self, "llm", "model", "orcarouter/auto")
        catalog = self._catalog(["orcarouter/auto", "vision/model"])

        with patch.object(orcarouter, "fetch_catalog", return_value=catalog):
            status, out, err = self._run(["--json"])

        payload = json.loads(out)
        self.assertEqual(status, 0)
        self.assertEqual(
            [m["id"] for m in payload["models"]], ["orcarouter/auto", "vision/model"]
        )
        self.assertTrue(payload["configured_model_compatible"])
        self.assertEqual(err, "")

    def test_removed_model_is_reported_incompatible(self) -> None:
        override_option(self, "llm", "api_key", FAKE_KEY)
        override_option(self, "llm", "model", "text/model")
        catalog = self._catalog(["vision/model"])

        with patch.object(orcarouter, "fetch_catalog", return_value=catalog):
            status, out, err = self._run(["--json"])

        payload = json.loads(out)
        self.assertEqual(status, 0)
        self.assertFalse(payload["configured_model_compatible"])
        self.assertIn("is not in the current", err)

    def test_degraded_catalog_is_labelled_and_uses_the_seed(self) -> None:
        override_option(self, "llm", "api_key", FAKE_KEY)
        degraded = orcarouter.CatalogResult(
            models=orcarouter.seed_models("chat"),
            source="seed",
            degraded=True,
            error="live catalog unavailable",
            error_kind="network",
        )

        with patch.object(orcarouter, "fetch_catalog", return_value=degraded):
            status, out, _err = self._run([])

        self.assertEqual(status, 0)
        self.assertIn("WARNING", out)
        self.assertIn("degraded", out)
        self.assertIn("orcarouter/auto", out)

    def test_missing_key_is_an_actionable_error(self) -> None:
        status, _out, err = self._run([])

        self.assertEqual(status, 3)
        self.assertIn("cowrie-orcarouter-auth", err)


class AuthCliTests(TempCredentialCase):
    def test_api_key_flag_stores_a_masked_credential(self) -> None:
        out = StringIO()
        with (
            patch.object(getpass, "getpass", return_value=FAKE_KEY),
            redirect_stdout(out),
        ):
            status = orcarouter_auth.main(["--api-key"])

        self.assertEqual(status, 0)
        self.assertNotIn(FAKE_KEY, out.getvalue())
        loaded = orcarouter.CredentialStore().load()
        assert loaded is not None
        self.assertEqual(loaded.key, FAKE_KEY)

    def test_status_never_prints_the_key(self) -> None:
        orcarouter.CredentialStore().save(orcarouter.Credential(key=FAKE_KEY))
        out = StringIO()
        with redirect_stdout(out):
            status = orcarouter_auth.main(["--status"])

        self.assertEqual(status, 0)
        self.assertNotIn(FAKE_KEY, out.getvalue())
        self.assertIn("sk-orca-…0001", out.getvalue())

    def test_clear_removes_the_credential(self) -> None:
        orcarouter.CredentialStore().save(orcarouter.Credential(key=FAKE_KEY))
        out = StringIO()
        with redirect_stdout(out):
            status = orcarouter_auth.main(["--clear"])

        self.assertEqual(status, 0)
        self.assertIsNone(orcarouter.CredentialStore().load())

    def test_pkce_cli_end_to_end_persists_the_exchanged_key(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("POST", "/api/v1/auth/keys")] = (
                200,
                {"key": FAKE_KEY, "scope": "api", "user_id": "9"},
            )
            out = StringIO()
            with (
                patch.dict(os.environ, {"ORCA_AUTH_BASE_URL": server.url}),
                patch.object(webbrowser, "open"),
                redirect_stdout(out),
            ):
                with patch.object(builtins, "input", return_value="shown-code"):
                    status = orcarouter_auth.main([])

            self.assertEqual(status, 0)
            request = server.requests[-1]
            self.assertEqual(request["path"], "/api/v1/auth/keys")
            self.assertNotIn("shown-code", request["path"])
            body = json.loads(request["body"])
            self.assertNotIn(body["code_verifier"], out.getvalue())

        loaded = orcarouter.CredentialStore().load()
        assert loaded is not None
        self.assertEqual(loaded.key, FAKE_KEY)
        self.assertEqual(loaded.source, "pkce")
        self.assertNotIn(FAKE_KEY, out.getvalue())

    def test_failed_exchange_stores_nothing(self) -> None:
        with FakeOrcaServer() as server:
            server.routes[("POST", "/api/v1/auth/keys")] = (
                403,
                {"error": "access_denied"},
            )
            err = StringIO()
            with (
                patch.dict(os.environ, {"ORCA_AUTH_BASE_URL": server.url}),
                patch.object(webbrowser, "open"),
                redirect_stderr(err),
            ):
                with patch.object(builtins, "input", return_value="code"):
                    status = orcarouter_auth.main(["--no-browser"])

        self.assertEqual(status, 2)
        self.assertIn("403", err.getvalue())
        self.assertIsNone(orcarouter.CredentialStore().load())


class AuthFailureTests(TempCredentialCase):
    def _client_with_stored_key(self) -> llm_module.LLMClient:
        orcarouter.CredentialStore().save(orcarouter.Credential(key=FAKE_KEY))
        override_option(self, "llm", "provider", "orcarouter")
        return self.make_client()

    def test_401_marks_the_exact_generation_and_keeps_the_key(self) -> None:
        client = self._client_with_stored_key()
        self.assertEqual(client._credential_generation, 1)

        with patch.object(
            client, "_send_request", return_value=defer.succeed((401, b""))
        ):
            result = self._deferred_result(client.get_response(["system", "User: id"]))

        self.assertEqual(result, "")
        loaded = orcarouter.CredentialStore().load()
        assert loaded is not None
        self.assertTrue(loaded.needs_reauth)
        self.assertEqual(loaded.key, FAKE_KEY)
        self.assertEqual(loaded.generation, 1)

    def test_stale_401_cannot_taint_a_newer_credential(self) -> None:
        client = self._client_with_stored_key()
        store = orcarouter.CredentialStore()
        store.save(orcarouter.Credential(key=FAKE_KEY_TWO))

        client._handle_auth_failure()

        loaded = store.load()
        assert loaded is not None
        self.assertFalse(loaded.needs_reauth)
        self.assertEqual(loaded.key, FAKE_KEY_TWO)
        self.assertEqual(loaded.generation, 2)

    def test_403_does_not_trigger_reauthentication(self) -> None:
        client = self._client_with_stored_key()

        with patch.object(
            client, "_send_request", return_value=defer.succeed((403, b""))
        ):
            self._deferred_result(client.get_response(["system", "User: id"]))

        loaded = orcarouter.CredentialStore().load()
        assert loaded is not None
        self.assertFalse(loaded.needs_reauth)

    def test_reauth_state_prevents_sending_the_dead_key(self) -> None:
        client = self._client_with_stored_key()
        client._handle_auth_failure()

        rebuilt = self.make_client()

        self.assertEqual(rebuilt.api_key, "")
        self.assertEqual(rebuilt._key_source, "needs_reauth")

    def test_no_secret_is_logged_on_401(self) -> None:
        client = self._client_with_stored_key()
        with (
            patch.object(llm_module.LLMClient, "_log") as logger,
            patch.object(
                client, "_send_request", return_value=defer.succeed((401, b""))
            ),
        ):
            self._deferred_result(client.get_response(["system", "User: id"]))

        for call in logger.error.call_args_list:
            self.assertNotIn(FAKE_KEY, call.args[0])


if __name__ == "__main__":
    unittest.main()
