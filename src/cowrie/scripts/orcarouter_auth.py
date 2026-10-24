# SPDX-FileCopyrightText: 2026 OrcaRouter
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: CLI for the two OrcaRouter credential choices: paste an existing
# ABOUTME: sk-orca- API key, or sign in with OAuth 2.0 + PKCE (out-of-band).

from __future__ import annotations

import argparse
import getpass
import sys
import webbrowser

from cowrie.llm import orcarouter


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cowrie-orcarouter-auth",
        description=(
            f"Connect this Cowrie install to {orcarouter.PROVIDER_LABEL}. "
            "Without arguments it starts a browser sign-in (OAuth 2.0 + PKCE) "
            "and stores the resulting key; --api-key stores a key you already have."
        ),
        epilog=(
            f"Models: https://www.orcarouter.ai/models?tier=cyber · "
            f"Provider: {orcarouter.PROVIDER_URL} · "
            f"Authorized apps: {orcarouter.KEY_DASHBOARD_URL}"
        ),
    )
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument(
        "--api-key",
        action="store_true",
        help="prompt for an existing sk-orca-… key instead of a browser login",
    )
    choice.add_argument(
        "--status", action="store_true", help="show the stored credential (masked)"
    )
    choice.add_argument(
        "--clear", action="store_true", help="remove the stored credential"
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="print the authorization URL instead of opening a browser",
    )
    parser.add_argument(
        "--app-name",
        default=orcarouter.APP_NAME,
        help="label shown on the consent screen (default: %(default)s)",
    )
    return parser


def _print_status() -> int:
    store = orcarouter.CredentialStore()
    try:
        credential = store.load()
    except orcarouter.OrcaRouterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if credential is None:
        print(
            "No OrcaRouter credential stored. Run `cowrie-orcarouter-auth` for a "
            "browser sign-in, or `cowrie-orcarouter-auth --api-key` to paste a key."
        )
        return 1
    state = "needs reauthentication" if credential.needs_reauth else "ready"
    print(f"Provider: {orcarouter.PROVIDER_LABEL}")
    print(f"Credential: {credential.masked} ({credential.source})")
    print(f"Scope: {credential.scope}")
    print(f"State: {state}")
    print(f"File: {store.path}")
    return 0 if not credential.needs_reauth else 1


def _connect_with_api_key() -> int:
    key = getpass.getpass("OrcaRouter API key (sk-orca-…): ")
    try:
        credential = orcarouter.store_api_key(key)
    except orcarouter.OrcaRouterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Stored OrcaRouter API key {credential.masked}.")
    print(f"Then set [llm] provider = {orcarouter.PROVIDER_ID} in cowrie.cfg.")
    return 0


def _connect_with_pkce(no_browser: bool, app_name: str) -> int:
    try:
        pending = orcarouter.begin_login(app_name=app_name)
    except orcarouter.OrcaRouterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"{orcarouter.PROVIDER_LABEL}: authorize this Cowrie install at:")
    print()
    print(pending.authorize_url)
    print()
    print(
        "After you approve, the consent screen shows a code. Copy it into the "
        "prompt below; it is valid for 10 minutes and can be used once."
    )
    if not no_browser:
        try:
            webbrowser.open(pending.authorize_url)
        except webbrowser.Error:
            pass
    try:
        code = input("Authorization code: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nerror: sign-in cancelled; nothing was stored.", file=sys.stderr)
        return 130
    if not code:
        print("error: no code entered; nothing was stored.", file=sys.stderr)
        return 2

    try:
        credential = orcarouter.exchange_code(pending, code)
        orcarouter.CredentialStore().save(credential)
    except orcarouter.OrcaRouterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    who = credential.user_id or "the authorized account"
    print(
        f"Connected {who} to {orcarouter.PROVIDER_LABEL}; stored credential "
        f"{credential.masked} (scope {credential.scope})."
    )
    print(
        f"Set [llm] provider = {orcarouter.PROVIDER_ID} in cowrie.cfg and pick a "
        f"model with `cowrie-orcarouter-models` (default: {orcarouter.DEFAULT_MODEL})."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.status:
        return _print_status()
    if args.clear:
        try:
            removed = orcarouter.CredentialStore().clear()
        except orcarouter.OrcaRouterError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(
            "Removed the stored OrcaRouter credential."
            if removed
            else "No stored credential to remove."
        )
        return 0
    if args.api_key:
        return _connect_with_api_key()
    return _connect_with_pkce(args.no_browser, args.app_name)


def run() -> None:
    raise SystemExit(main(sys.argv[1:]))


if __name__ == "__main__":
    run()
