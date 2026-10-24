# SPDX-FileCopyrightText: 2026 OrcaRouter
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Live connectivity checks for the OrcaRouter provider. Run only when
# ABOUTME: ORCAROUTER_API_KEY is set; they exercise the same code path Cowrie
# ABOUTME: uses in production, not an ad-hoc curl.

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from twisted.internet import task

from cowrie.core.config import CowrieConfig
from cowrie.llm import llm as llm_module
from cowrie.llm import orcarouter

LIVE_KEY = os.environ.get("ORCAROUTER_API_KEY", "")

# Verification key model. The provider's documented default for users is
# orcarouter/auto; the cyber-tier models need a business-verified workspace,
# so the connectivity probe uses a model this key can actually call.
LIVE_MODEL = "deepseek/deepseek-v4.1-flash"


@unittest.skipUnless(LIVE_KEY, "ORCAROUTER_API_KEY is not set")
class OrcaRouterLiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._saved: dict[str, str | None] = {}
        for option, value in (
            ("provider", orcarouter.PROVIDER_ID),
            ("api_key", LIVE_KEY),
            ("model", LIVE_MODEL),
            ("credentials_file", str(Path(self._tmp.name) / "orcarouter.json")),
        ):
            self._saved[option] = CowrieConfig.get("llm", option, fallback=None)
            CowrieConfig.set("llm", option, value)
        llm_module.reset_shared_client()
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        for option, previous in self._saved.items():
            if previous is None:
                CowrieConfig.remove_option("llm", option)
            else:
                CowrieConfig.set("llm", option, previous)
        llm_module.reset_shared_client()

    def _chat(self, prompt: list[str]) -> str:
        captured: dict[str, Any] = {}

        def main(_reactor: Any) -> Any:
            deferred = llm_module.get_shared_client().get_response(prompt)
            deferred.addCallback(lambda text: captured.setdefault("text", text))
            return deferred

        try:
            task.react(main)
        except SystemExit as exc:  # task.react stops the reactor this way
            if exc.code not in (0, None):
                raise
        return str(captured.get("text", ""))

    def test_live_provider_end_to_end(self) -> None:
        client = llm_module.get_shared_client()
        self.assertEqual(client.provider, orcarouter.PROVIDER_ID)
        self.assertEqual(client.host, "https://api.orcarouter.ai")
        self.assertEqual(client.model, LIVE_MODEL)

        chat_catalog = orcarouter.fetch_catalog(
            LIVE_KEY, capability="chat", use_cache=False
        )
        self.assertFalse(chat_catalog.degraded, chat_catalog.error)
        self.assertEqual(chat_catalog.source, "live")
        self.assertGreater(len(chat_catalog.models), 0)
        self.assertIn(LIVE_MODEL, [model.id for model in chat_catalog.models])

        image_catalog = orcarouter.fetch_catalog(
            LIVE_KEY, capability="chat", modality="image", use_cache=False
        )
        self.assertFalse(image_catalog.degraded, image_catalog.error)
        for model in image_catalog.models:
            self.assertIn("image", model.input_modalities)

        text = self._chat(
            [
                "You are a Linux shell simulator. Reply with the output only.",
                "User: echo orcarouter-live-check",
            ]
        )
        self.assertTrue(text.strip(), "the provider returned an empty completion")


if __name__ == "__main__":
    unittest.main()
