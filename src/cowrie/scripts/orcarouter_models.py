# SPDX-FileCopyrightText: 2026 OrcaRouter
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: CLI that lists OrcaRouter Cyber Inference models for a capability
# ABOUTME: from the live catalog, with a verified fallback when it is unreachable.

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from cowrie.core.config import CowrieConfig
from cowrie.llm import orcarouter


def _resolve_key() -> tuple[str, str]:
    configured = CowrieConfig.get("llm", "api_key", fallback="").strip()
    if configured:
        return configured, "config"
    try:
        credential = orcarouter.CredentialStore().load()
    except orcarouter.OrcaRouterError as exc:
        print(f"warning: {exc}", file=sys.stderr)
        return "", "none"
    if credential is None:
        return "", "none"
    if credential.needs_reauth:
        return "", "needs_reauth"
    return credential.key, "credentials_file"


def _format_model(model: orcarouter.ModelInfo) -> str:
    parts = [model.id]
    if model.context_length:
        parts.append(f"context {model.context_length}")
    modalities = ",".join(model.input_modalities) or "undeclared"
    parts.append(f"inputs {modalities}")
    if model.reasoning_efforts:
        parts.append("reasoning " + "/".join(model.reasoning_efforts))
    elif model.reasoning:
        parts.append("reasoning")
    return "  ".join(parts)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cowrie-orcarouter-models",
        description=(
            f"List {orcarouter.PROVIDER_LABEL} models for one capability, read "
            "from the live OrcaRouter catalog. Choose an id for [llm] model."
        ),
    )
    parser.add_argument(
        "--capability",
        choices=orcarouter.CAPABILITIES,
        default="chat",
        help="model capability to list (default: %(default)s)",
    )
    parser.add_argument(
        "--modality",
        choices=orcarouter.MODALITIES,
        default=None,
        help="for chat, require this input modality (e.g. image)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="do not fall back to the last known-good catalog",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    key, source = _resolve_key()
    if not key:
        if source == "needs_reauth":
            print(
                "error: the stored OrcaRouter credential needs reauthentication; "
                "run `cowrie-orcarouter-auth`.",
                file=sys.stderr,
            )
        else:
            print(
                "error: no OrcaRouter API key found; run `cowrie-orcarouter-auth` "
                "or set [llm] api_key.",
                file=sys.stderr,
            )
        return 3

    result = orcarouter.fetch_catalog(
        key,
        capability=args.capability,
        modality=args.modality,
        use_cache=not args.no_cache,
    )
    configured = CowrieConfig.get("llm", "model", fallback="").strip()
    compatible = (
        configured in [model.id for model in result.models] if configured else None
    )
    if compatible is False:
        print(
            f"WARNING: [llm] model = {configured} is not in the current "
            f"{args.capability} options; choose one of the ids listed.",
            file=sys.stderr,
        )

    if args.json:
        payload: dict[str, Any] = result.as_dict()
        payload["configured_model"] = configured
        payload["configured_model_compatible"] = compatible
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    title = args.capability
    if args.modality:
        title += f" ({args.modality} input)"
    print(f"{orcarouter.PROVIDER_LABEL} — {title} models")
    if result.degraded:
        print(f"WARNING: live catalog unavailable: {result.error}")
        print(f"Showing {result.source}-based verified fallback (degraded).")
    else:
        print(f"Live catalog: {orcarouter.api_base_url()}{orcarouter.MODELS_PATH}")
    print()

    if not result.models:
        print(
            "No models matched. Check the API key's access, or retry with "
            "`--no-cache` once the catalog is reachable."
        )
        return 0

    for index, model in enumerate(result.models, start=1):
        print(f"{index:>3}. {_format_model(model)}")

    return 0


def run() -> None:
    raise SystemExit(main(sys.argv[1:]))


if __name__ == "__main__":
    run()
