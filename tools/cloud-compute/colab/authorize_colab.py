#!/usr/bin/env python3
"""Authorize the pinned official Colab SDK without enabling its debug logger.

Run in the ROG user's interactive terminal. The Google authorization code is
read with terminal echo disabled; never pass it in argv, environment, or chat.
Only an authorization URL and allowlisted account metadata reach stdout.

Audited against googlecolab/google-colab-cli commit
d2d97794941723ab806c0f3642416691a951ec7d. Installation identity is verified by
the deployment manifest, not inferred from this helper's presence.
"""

from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import getpass
import hmac
from importlib import metadata
import io
import json
import logging
import os
import stat
import sys
from urllib.parse import parse_qs, urlsplit
import uuid
import warnings


class AuthFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def emit(value: dict, stream) -> None:
    stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
    stream.flush()


_STATUS_FIELDS = frozenset(
    {
        "status", "error_code", "account_email", "scopes", "expires_in_seconds",
        "credential_storage", "refresh_token_persistence_verified", "sdk_version",
        "authenticated_at",
    }
)


def _open_status_parent(path: str) -> tuple[int, str]:
    """Open a private, owned parent through symlink-free directory descriptors."""
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 4096:
        raise AuthFailure("AUTH_STATUS_PATH_UNSAFE")
    parts = path.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise AuthFailure("AUTH_STATUS_PATH_UNSAFE")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    uid = os.getuid()
    fd = os.open("/", flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, uid) or info.st_mode & 0o022:
                raise AuthFailure("AUTH_STATUS_PATH_UNSAFE")
        parent = os.fstat(fd)
        if parent.st_uid != uid or parent.st_mode & 0o022:
            raise AuthFailure("AUTH_STATUS_PATH_UNSAFE")
        try:
            target = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            target = None
        if target and (
            not stat.S_ISREG(target.st_mode)
            or target.st_uid != uid
            or target.st_nlink != 1
        ):
            raise AuthFailure("AUTH_STATUS_PATH_UNSAFE")
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def write_status(path: str | None, value: dict) -> None:
    """Persist only allowlisted metadata; authorization URLs are never saved."""
    if not path:
        return
    parent_fd = None
    temp_name = None
    try:
        parent_fd, name = _open_status_parent(path)
        safe_value = {key: val for key, val in value.items() if key in _STATUS_FIELDS}
        encoded = (json.dumps(safe_value, ensure_ascii=False, sort_keys=True) + "\n").encode()
        if len(encoded) > 32768:
            raise AuthFailure("AUTH_STATUS_TOO_LARGE")
        temp_name = ".auth-status-" + uuid.uuid4().hex + ".tmp"
        output_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        with os.fdopen(output_fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_name = None
        os.fsync(parent_fd)
    except AuthFailure:
        raise
    except Exception:
        raise AuthFailure("AUTH_STATUS_WRITE_FAILED") from None
    finally:
        if parent_fd is not None:
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)


def preflight_keyring(auth) -> None:
    """Inspect Linux SecretService metadata without reading or unlocking secrets."""
    if sys.platform != "linux":
        raise AuthFailure("AUTH_KEYRING_PLATFORM_UNVERIFIED")

    def inspect_collection() -> bool:
        import keyring
        from keyring.backends import SecretService, chainer
        import secretstorage

        backend = keyring.get_keyring()
        if isinstance(backend, chainer.ChainerBackend):
            backend = backend.backends[0] if backend.backends else None
        if not isinstance(backend, SecretService.Keyring):
            raise AuthFailure("AUTH_KEYRING_BACKEND_UNVERIFIED")
        with contextlib.closing(secretstorage.dbus_init()) as bus:
            preferred = getattr(backend, "preferred_collection", None)
            collection = (
                secretstorage.Collection(bus, preferred)
                if preferred else secretstorage.Collection(bus)
            )
            return bool(collection.is_locked())

    try:
        locked = auth._run_with_timeout(inspect_collection, timeout=5.0)
    except AuthFailure:
        raise
    except TimeoutError:
        raise AuthFailure("AUTH_KEYRING_PROBE_TIMEOUT") from None
    except Exception:
        raise AuthFailure("AUTH_KEYRING_UNAVAILABLE") from None
    if locked:
        raise AuthFailure("AUTH_KEYRING_LOCKED")


def authorization_url(captured: str) -> str:
    """Extract only a Google OAuth authorization URL from SDK diagnostic text."""
    for line in reversed(captured.splitlines()):
        candidate = line.strip()
        if not candidate.startswith("https://accounts.google.com/"):
            continue
        parsed = urlsplit(candidate)
        if parsed.hostname != "accounts.google.com" or parsed.port not in (None, 443):
            continue
        if parsed.username or parsed.password or parsed.fragment:
            continue
        if parsed.path not in ("/o/oauth2/auth", "/o/oauth2/v2/auth"):
            continue
        query = parse_qs(parsed.query)
        if set(query) & {"access_token", "refresh_token", "id_token", "code"}:
            continue
        if query.get("response_type") != ["code"]:
            continue
        return candidate
    raise AuthFailure("AUTHORIZATION_URL_UNAVAILABLE")


def loopback_flow(auth, client_config: dict, args, out):
    """Use Google's installed-app PKCE callback; never copy codes via terminals."""
    if args.non_interactive:
        raise AuthFailure("AUTH_USER_INTERACTION_REQUIRED")
    preflight_keyring(auth)
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_config(
        client_config, auth.PUBLIC_SCOPES, autogenerate_code_verifier=True
    )
    pending = {"status": "authorization_required",
               "error_code": "AUTH_BROWSER_CONSENT_REQUIRED"}
    write_status(args.status_file, pending)
    emit(pending, out)
    return flow.run_local_server(
        host="localhost", bind_addr="127.0.0.1", port=0,
        open_browser=True, timeout_seconds=300,
        authorization_prompt_message=None,
        success_message=("Google callback received. Credential verification and secure "
                         "storage are still in progress. Check the Hepta authorization "
                         "status; this browser page is not proof of authorization."),
        prompt="consent",
    )


def authorize(args: argparse.Namespace, out, err) -> dict:
    # The stock CLI callback installs DEBUG file logging, and its Client logs
    # request headers and responses. Do not call cli.main/setup_logging here.
    logging.disable(logging.CRITICAL)
    capture = io.StringIO()
    try:
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            from colab_cli import auth
            import requests
    except ImportError:
        raise AuthFailure("AUTH_DEPENDENCIES_MISSING") from None

    if not hasattr(auth, "_get_token_from_keyring"):
        # Published 0.7.5 stores plaintext tokens. This helper deliberately
        # requires the audited newer SDK with the OS-keyring implementation.
        raise AuthFailure("AUTH_SDK_KEYRING_SUPPORT_REQUIRED")

    def hidden_code_input(_prompt: str = "") -> str:
        preflight_keyring(auth)
        url = authorization_url(capture.getvalue())
        write_status(args.status_file, {
            "status": "authorization_required",
            "error_code": "AUTH_USER_INTERACTION_REQUIRED",
        })
        emit({"status": "authorization_required", "authorization_url": url}, out)
        if args.non_interactive:
            raise AuthFailure("AUTH_USER_INTERACTION_REQUIRED")
        if sys.stdin is None or not sys.stdin.isatty():
            raise AuthFailure("AUTH_INTERACTIVE_TERMINAL_REQUIRED")
        if args.open_browser:
            # Uses the user's normal browser; no browser profile or cookies
            # are read. Whether a tab really opened is not asserted here.
            import webbrowser

            try:
                webbrowser.open(url, new=2)
            except Exception:
                pass
        err.write(
            "请先在 Google 页面完成授权，直到页面显示「一次性授权码」。\n"
            "复制该授权码，切回这个 ROG 本机终端，按 Ctrl+Shift+V 粘贴，再按回车。\n"
            "输入时不会显示任何字符或星号，这是正常的隐藏输入。不要把授权码贴到聊天里。\n"
            "如需中止，请按 Ctrl+C。\n"
        )
        err.flush()
        while True:
            try:
                with warnings.catch_warnings():
                    # getpass normally falls back to echoing if terminal control
                    # fails. Turn that warning into an error before any read.
                    warnings.simplefilter("error", getpass.GetPassWarning)
                    code = getpass.getpass(
                        "请粘贴 Google 一次性授权码，然后回车（输入隐藏）： ", stream=err
                    ).strip()
            except (getpass.GetPassWarning, EOFError, OSError):
                raise AuthFailure("AUTH_HIDDEN_INPUT_UNAVAILABLE") from None
            if code:
                return code
            # Keep the original SDK flow and authorization URL. A blank Enter
            # must not exchange a code, restart OAuth, or close the terminal.
            err.write(
                "尚未输入授权码，授权仍在等待。请从同一 Google 页面复制授权码，\n"
                "回到此终端按 Ctrl+Shift+V 粘贴后回车；输入不显示是正常现象。\n"
            )
            err.flush()

    marker = object()
    previous_input = auth.__dict__.get("input", marker)
    auth.input = hidden_code_input
    previous_remote_flow = auth.__dict__.get("_run_remote_flow", marker)
    if getattr(args, "loopback", False):
        auth._run_remote_flow = lambda config: loopback_flow(auth, config, args, out)
    session = None
    try:
        # The SDK's normal warnings and HTTP exceptions are retained only in
        # memory. They are never emitted, saved, or returned as tool output.
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                preflight_keyring(auth)
                session = auth.get_credentials(provider=auth.AuthProvider.OAUTH2)
                creds = session.credentials
                if not creds.valid or not creds.token:
                    raise AuthFailure("AUTH_CREDENTIALS_INVALID")
                if not creds.refresh_token:
                    raise AuthFailure("AUTH_REFRESH_TOKEN_MISSING")
                preflight_keyring(auth)
                try:
                    persisted = auth._get_token_from_keyring()
                    persisted_data = json.loads(persisted) if persisted else {}
                except Exception:
                    raise AuthFailure("AUTH_KEYRING_PERSISTENCE_UNVERIFIED") from None
                saved_refresh = persisted_data.get("refresh_token")
                if not isinstance(saved_refresh, str) or not hmac.compare_digest(
                    saved_refresh, creds.refresh_token
                ):
                    raise AuthFailure("AUTH_KEYRING_PERSISTENCE_UNVERIFIED")
                # This is the same official tokeninfo operation used by
                # colab_cli.commands.utility.whoami. Logging is disabled and
                # no request URL, credential, raw response, or exception is
                # returned. The token is sent only to its Google issuer.
                response = requests.get(
                    "https://oauth2.googleapis.com/tokeninfo",
                    params={"access_token": creds.token},
                    timeout=20,
                    allow_redirects=False,
                )
                if response.status_code != 200:
                    raise AuthFailure("AUTH_TOKENINFO_REJECTED")
                try:
                    info = response.json()
                except ValueError:
                    raise AuthFailure("AUTH_TOKENINFO_INVALID") from None
                if not isinstance(info, dict):
                    raise AuthFailure("AUTH_TOKENINFO_INVALID")
                email = info.get("email")
                if not isinstance(email, str) or not email or len(email) > 512:
                    raise AuthFailure("AUTH_ACCOUNT_UNVERIFIED")
                if args.expected_account and email.casefold() != args.expected_account.casefold():
                    raise AuthFailure("AUTH_ACCOUNT_MISMATCH")
                scope = info.get("scope")
                if not isinstance(scope, str) or len(scope) > 16384:
                    raise AuthFailure("AUTH_SCOPES_UNVERIFIED")
                scopes = sorted(set(scope.split()))
                if "https://www.googleapis.com/auth/colaboratory" not in scopes:
                    raise AuthFailure("AUTH_COLAB_SCOPE_MISSING")
                try:
                    expires_in = int(info.get("expires_in", 0))
                except (TypeError, ValueError):
                    raise AuthFailure("AUTH_EXPIRY_UNVERIFIED") from None
                if expires_in <= 0:
                    raise AuthFailure("AUTH_CREDENTIALS_EXPIRED")
                return {
                    "status": "authorized",
                    "account_email": email,
                    "scopes": scopes,
                    "expires_in_seconds": expires_in,
                    "credential_storage": "os_keyring",
                    "refresh_token_persistence_verified": True,
                    "sdk_version": metadata.version("google-colab-cli"),
                    "authenticated_at": datetime.now(timezone.utc).isoformat(),
                }
    finally:
        if previous_input is marker:
            auth.__dict__.pop("input", None)
        else:
            auth.input = previous_input
        if previous_remote_flow is marker:
            auth.__dict__.pop("_run_remote_flow", None)
        else:
            auth._run_remote_flow = previous_remote_flow
        if session is not None:
            session.close()
        capture.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-account", help="Optional exact Google account email")
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--loopback", action="store_true",
                        help="Authorize in the local browser with a loopback PKCE callback")
    parser.add_argument(
        "--status-file",
        help="Absolute file in an existing owned directory for safe JSON status",
    )
    args = parser.parse_args()
    out, err = sys.stdout, sys.stderr
    os.umask(0o077)
    exit_code = 0
    try:
        if args.status_file:
            parent_fd, _ = _open_status_parent(args.status_file)
            os.close(parent_fd)
        result = authorize(args, out, err)
    except AuthFailure as exc:
        result = {"status": "blocked", "error_code": exc.code}
        exit_code = 2
    except KeyboardInterrupt:
        result = {"status": "cancelled", "error_code": "AUTH_CANCELLED"}
        exit_code = 130
    except Exception as exc:
        # Exception strings and tracebacks may contain tokens or URLs.
        safe_codes = {
            "InvalidGrantError": "AUTH_CODE_REJECTED",
            "AccessDeniedError": "AUTH_CONSENT_DENIED",
            "MismatchingStateError": "AUTH_STATE_MISMATCH",
            "MissingCodeError": "AUTH_CALLBACK_CODE_MISSING",
            "WSGITimeoutError": "AUTH_BROWSER_CALLBACK_TIMEOUT",
            "Timeout": "AUTH_NETWORK_TIMEOUT",
            "ConnectTimeout": "AUTH_NETWORK_TIMEOUT",
            "ReadTimeout": "AUTH_NETWORK_TIMEOUT",
            "ConnectionError": "AUTH_NETWORK_CONNECTION_FAILED",
            "SSLError": "AUTH_TLS_FAILED",
        }
        code = safe_codes.get(type(exc).__name__, "AUTH_FLOW_FAILED")
        if isinstance(exc, Warning) and getattr(exc, "old_scope", None) is not None:
            code = "AUTH_SCOPE_CHANGED"
        result = {"status": "blocked", "error_code": code}
        exit_code = 2
    try:
        write_status(args.status_file, result)
    except AuthFailure as exc:
        result = {"status": "blocked", "error_code": exc.code}
        exit_code = 2
    emit(result, out)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

