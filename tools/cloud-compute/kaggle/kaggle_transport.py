"""Bounded transport for official Kaggle SDK RPC definitions.

No automatic replay of a write, no credential-bearing redirects, and no
credential values in errors. The SDK supplies request types/serialization;
this module supplies explicit timeouts and bounded response handling.
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
from urllib.parse import urlparse, urljoin
import urllib.error
import urllib.request


API_ORIGIN = "https://api.kaggle.com"
SDK_SNAPSHOT = "46efde203816039e34205bb6cd62ad57d946c25a"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_ERROR_BYTES = 64 * 1024
_KNOWN_SECRETS: set[str] = set()
_RPC_STATUS_NAMES = frozenset({"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND",
    "ALREADY_EXISTS", "PERMISSION_DENIED", "UNAUTHENTICATED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
    "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS"})
_PERMISSION_NAME = r"([A-Za-z][A-Za-z0-9]{0,63}\.[a-z][A-Za-z0-9]{0,31})"


class AdapterError(Exception):
    def __init__(self, code: str, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.code, self.message, self.details = code, message, details or {}

    def as_dict(self):
        return {"code": self.code, "message": self.message, "details": scrub(self.details)}


class RemoteError(AdapterError):
    def __init__(self, code: str, message: str, *, status: int | None = None, ambiguous: bool = False, diagnostics: dict | None = None):
        super().__init__(code, message, details={**(diagnostics or {}), "http_status": status, "remote_effect_unknown": ambiguous})
        self.status, self.ambiguous = status, ambiguous


def remember_secret(secret: Any):
    if isinstance(secret, str) and len(secret) >= 8:
        _KNOWN_SECRETS.add(secret)


def _public_url(match):
    value = match.group(0)
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        storage = (host == "kaggleusercontent.com" or host.endswith(".kaggleusercontent.com")
                   or host in {"storage.googleapis.com", "storage.cloud.google.com"}
                   or host.endswith(".storage.googleapis.com"))
        if storage:
            # Kaggle output capabilities can be a five-part JWE in the PATH,
            # with no query string. Treat the entire storage path as secret.
            return parsed.scheme + "://" + host + "/[REDACTED_STORAGE_URL]"
        if parsed.username is not None or parsed.password is not None:
            return parsed.scheme + "://" + host + "/[REDACTED_URL]"
    except ValueError:
        return "[REDACTED_URL]"
    return value.split("?", 1)[0].split("#", 1)[0] + ("?[REDACTED_QUERY]" if "?" in value else "")


def scrub(value: Any) -> Any:
    """Redact active credentials and common credential forms from receipts."""
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if isinstance(v, str) and re.search(r"^(authorization|proxy.authorization|cookie|set.cookie|access.token|refresh.token|password|api.key|token)$", str(k), re.I) else scrub(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(x) for x in value]
    if not isinstance(value, str):
        return value
    for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"\bKGAT[_-]?[A-Za-z0-9._~-]{12,}", "[REDACTED_KAGGLE_TOKEN]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED_JWT]", value)
    value = re.sub(r"(?im)^\s*((?:proxy-)?authorization|(?:set-)?cookie)\s*[:=].*$", r"\1: [REDACTED]", value)
    # Signed download/connection URLs can themselves be bearer credentials.
    value = re.sub(r"https?://[^\s\"'<>]+", _public_url, value, flags=re.I)
    return value


def safe_http_error_diagnostics(error, action):
    """Read <=64 KiB; return only typed allowlisted fields, never body text."""
    details = {"rpc_action": action}
    try:
        body = error.read(MAX_ERROR_BYTES)
        if len(body) >= MAX_ERROR_BYTES: return details
        result = json.loads(body)
        entry = result.get("error") if isinstance(result, dict) else None
        if not isinstance(entry, dict): return details
        code = entry.get("code")
        if type(code) is int and 0 <= code <= 599: details["api_error_code"] = code
        status = entry.get("status")
        if isinstance(status, str) and status in _RPC_STATUS_NAMES: details["api_error_status"] = status
        message = entry.get("message")
        if not isinstance(message, str) or len(message) > 512: return details
        for field, pattern in (("required_permission", r"Required permission '" + _PERMISSION_NAME + r"' was not satisfied\.?"),
                               ("denied_permission", r"Permission '" + _PERMISSION_NAME + r"' was denied\.?")):
            match = re.fullmatch(pattern, message)
            if match and scrub(match.group(1)) == match.group(1):
                details[field] = match.group(1)
                break
    except Exception:
        # Malformed JSON, truncated/failed reads, or unusual server responses
        # never expand the public diagnostic surface.
        pass
    finally:
        with contextlib.suppress(Exception): error.close()
    return details


def atomic_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise AdapterError("UNSAFE_PATH", "Refusing to replace a symlink.")
    fd, tmp = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
            f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        with contextlib.suppress(FileNotFoundError): os.unlink(tmp)


def private_read(path: Path, max_bytes: int = 128 * 1024) -> bytes:
    """Read only a current-user, regular credential file; never follow a link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_size > max_bytes:
            raise AdapterError("UNSAFE_CREDENTIAL_FILE", "Credential file owner/type/size validation failed.")
        if s.st_mode & 0o077:
            raise AdapterError("CREDENTIAL_PERMISSIONS", "Credential file must not be accessible to group or other users.")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise AdapterError("CREDENTIAL_TOO_LARGE", "Credential file exceeds its bound.")
        return data
    finally:
        os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


RPC = {
    "quota": ("kernels.KernelsApiService", "GetAcceleratorQuotaStatistics", "kagglesdk.kernels.types.kernels_api_service", "ApiGetAcceleratorQuotaStatisticsRequest"),
    "list": ("kernels.KernelsApiService", "ListKernels", "kagglesdk.kernels.types.kernels_api_service", "ApiListKernelsRequest"),
    "get": ("kernels.KernelsApiService", "GetKernel", "kagglesdk.kernels.types.kernels_api_service", "ApiGetKernelRequest"),
    "submit": ("kernels.KernelsApiService", "SaveKernel", "kagglesdk.kernels.types.kernels_api_service", "ApiSaveKernelRequest"),
    "status": ("kernels.KernelsApiService", "GetKernelSessionStatus", "kagglesdk.kernels.types.kernels_api_service", "ApiGetKernelSessionStatusRequest"),
    "output": ("kernels.KernelsApiService", "ListKernelSessionOutput", "kagglesdk.kernels.types.kernels_api_service", "ApiListKernelSessionOutputRequest"),
    "files": ("kernels.KernelsApiService", "ListKernelFiles", "kagglesdk.kernels.types.kernels_api_service", "ApiListKernelFilesRequest"),
    "cancel": ("kernels.KernelsApiService", "CancelKernelSession", "kagglesdk.kernels.types.kernels_api_service", "ApiCancelKernelSessionRequest"),
    "introspect": ("security.OAuthService", "IntrospectToken", "kagglesdk.security.types.oauth_service", "IntrospectTokenRequest"),
    "refresh": ("users.AccountService", "GenerateAccessToken", "kagglesdk.users.types.account_service", "GenerateAccessTokenRequest"),
}


def sdk_payload(action: str, values: dict) -> dict:
    try:
        _, _, module, cls_name = RPC[action]
        cls = getattr(importlib.import_module(module), cls_name)
        obj = cls()
        enums = importlib.import_module("kagglesdk.kernels.types.kernels_enums")
        for key, value in values.items():
            if not isinstance(getattr(cls, key, None), property):
                raise AttributeError("Unknown SDK request field")
            if key == "kernel_execution_type": value = enums.KernelExecutionType[value]
            elif key == "group": value = enums.KernelsListViewType[value]
            elif key == "sort_by": value = enums.KernelsListSortType[value]
            elif key == "api_version":
                value = getattr(importlib.import_module("kagglesdk.users.types.account_service"), "ApiVersion")[value]
            elif key == "expiration_duration": value = dt.timedelta(seconds=value)
            setattr(obj, key, value)
        return obj.to_dict()
    except (ImportError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise AdapterError("SDK_CONTRACT", "Installed Kaggle SDK does not satisfy the pinned request contract.", details={"action": action, "type": type(exc).__name__}) from None


def dependency_versions() -> dict:
    out = {}
    for name in ("kaggle", "kagglesdk", "requests", "certifi", "python-dateutil", "six"):
        try: out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError: out[name] = None
    return out


class KaggleTransport:
    def __init__(self, *, timeout: int = 45, credentials_file: str | None = None, expected_username: str | None = None):
        if expected_username is not None and (not isinstance(expected_username, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", expected_username)):
            raise AdapterError("INVALID_EXPECTED_USERNAME", "Expected username must be a valid Kaggle account name.")
        self.expected_username = expected_username
        self.timeout = max(1, min(timeout, 120))
        self.opener = urllib.request.build_opener(NoRedirect())
        self.token: str | None = None
        self.basic: tuple[str, str] | None = None
        self.credential_method = "none"
        self.oauth_path = Path(credentials_file).expanduser() if credentials_file else Path.home() / ".kaggle/credentials.json"
        self._account = None
        self._loaded = False

    def _request(self, action: str, values: dict, *, mutation=False) -> dict:
        service, method, _, _ = RPC[action]
        payload = sdk_payload(action, values)
        headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "HeptaRuntime-Kaggle/0.1.7"}
        if self.token: headers["Authorization"] = "Bearer " + self.token
        elif self.basic:
            b64 = base64.b64encode((self.basic[0] + ":" + self.basic[1]).encode()).decode()
            remember_secret(b64)
            headers["Authorization"] = "Basic " + b64
        req = urllib.request.Request(API_ORIGIN + "/v1/" + service + "/" + method,
                                     data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise RemoteError("RESPONSE_TOO_LARGE", "Kaggle response exceeded the response limit.", ambiguous=mutation)
                if "application/json" not in response.headers.get("Content-Type", "").lower():
                    raise RemoteError("NON_JSON_RESPONSE", "Kaggle returned a non-JSON RPC response.", ambiguous=mutation)
                result = json.loads(body)
                if not isinstance(result, dict):
                    raise RemoteError("INVALID_RESPONSE", "Kaggle RPC response was not an object.", ambiguous=mutation)
                code = result.get("code")
                if isinstance(code, int) and code >= 400:
                    raise RemoteError("REMOTE_REJECTED", "Kaggle rejected the RPC.", status=code, ambiguous=mutation)
                return result
        except urllib.error.HTTPError as exc:
            diagnostics = safe_http_error_diagnostics(exc, action)
            # Do not include body, URL, request, headers, or the raw exception.
            raise RemoteError("HTTP_ERROR", "Kaggle HTTP request failed.", status=exc.code,
                              ambiguous=mutation, diagnostics=diagnostics) from None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise RemoteError("TRANSPORT_ERROR", "Kaggle transport did not yield a complete response.", ambiguous=mutation) from None

    def _load_credentials(self):
        if self._loaded: return
        self._loaded = True
        value = os.environ.get("KAGGLE_API_TOKEN")
        if value:
            # The official CLI also allows this variable to name a token file.
            if len(value) < 4096 and not value.startswith("KGAT") and Path(value).expanduser().is_file():
                value = private_read(Path(value).expanduser()).decode().strip()
            self.token, self.credential_method = value.strip(), "api_token"
        else:
            for name in ("access_token", "access_token.txt"):
                path = Path.home() / ".kaggle" / name
                if path.exists():
                    self.token = private_read(path).decode().strip()
                    self.credential_method = "api_token_file"
                    break
        if self.token:
            if any(c.isspace() for c in self.token):
                raise AdapterError("INVALID_CREDENTIAL", "API token must be a single non-whitespace value.")
            remember_secret(self.token); return
        user, key = os.environ.get("KAGGLE_USERNAME"), os.environ.get("KAGGLE_KEY")
        config_path = Path(os.environ.get("KAGGLE_CONFIG_DIR", str(Path.home() / ".kaggle"))) / "kaggle.json"
        if not (user and key) and config_path.exists():
            try:
                data = json.loads(private_read(config_path))
                user, key = data.get("username"), data.get("key")
            except (json.JSONDecodeError, UnicodeError):
                raise AdapterError("INVALID_CREDENTIAL_FILE", "Legacy Kaggle credential file is invalid.") from None
        if user and key:
            self.basic, self.credential_method = (user, key), "legacy_api_key"
            remember_secret(key); return
        if self.oauth_path.exists():
            lock = self.oauth_path.parent / ".hepta-credentials.lock"
            fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise AdapterError("AUTH_REFRESH_BUSY", "Another process is refreshing the shared OAuth credential; observe again shortly.") from None
                data = json.loads(private_read(self.oauth_path))
                refresh = data.get("refresh_token")
                access = data.get("access_token")
                remember_secret(refresh); remember_secret(access)
                if not refresh:
                    raise AdapterError("INVALID_OAUTH_CREDENTIAL", "OAuth credential lacks its refresh token.")
                try:
                    expires = dt.datetime.fromisoformat(data.get("access_token_expiration", "").replace("Z", "+00:00"))
                    if expires.tzinfo is None: expires = expires.replace(tzinfo=dt.timezone.utc)
                except (ValueError, TypeError): expires = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
                if not access or expires <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
                    result = self._request("refresh", {"refresh_token": refresh, "api_version": "API_VERSION_V1", "expiration_duration": 43200}, mutation=True)
                    access = result.get("token")
                    seconds = result.get("expiresIn")
                    if isinstance(seconds, str) and seconds.isdigit(): seconds = int(seconds)
                    if not isinstance(access, str) or not access or not isinstance(seconds, (int, float)) or seconds <= 0:
                        raise AdapterError("INVALID_REFRESH_RESPONSE", "OAuth refresh did not return a usable access token.")
                    remember_secret(access)
                    data["access_token"] = access
                    data["access_token_expiration"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()
                    atomic_json(self.oauth_path, data)
                self.token, self.credential_method = access, "oauth"
                remember_secret(access)
            except (json.JSONDecodeError, UnicodeError):
                raise AdapterError("INVALID_OAUTH_CREDENTIAL", "OAuth credential file is invalid.") from None
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
            return
        raise AdapterError("AUTH_REQUIRED", "Complete official Kaggle OAuth login or configure a local API token.")

    def _verify_expected_account(self, account):
        if self.expected_username is not None and account.get("username") != self.expected_username:
            raise AdapterError("AUTH_ACCOUNT_MISMATCH", "The active Kaggle account does not match the configured expected username.",
                               details={"expected_username": self.expected_username, "actual_username": account.get("username")})
        return account

    def account(self) -> dict:
        if self._account is not None: return self._verify_expected_account(self._account)
        self._load_credentials()
        if self.token:
            response = self._request("introspect", {"token": self.token})
            username = response.get("username")
            if not response.get("active") or not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", username):
                raise AdapterError("AUTH_INVALID", "Kaggle token introspection did not confirm an active account.")
            self._account = {"authenticated": True, "username": username,
                             "user_id": response.get("userId"), "scope": response.get("scope"),
                             "expires_unix": response.get("exp"), "method": self.credential_method,
                             "verification": "official_token_introspection"}
        elif self.basic:
            self._verify_expected_account({"username": self.basic[0]})
            self._request("quota", {})
            self._account = {"authenticated": True, "username": self.basic[0], "method": self.credential_method,
                             "verification": "authenticated_quota_with_configured_username"}
        return self._verify_expected_account(self._account)

    def call(self, action: str, values: dict, *, mutation=False) -> dict:
        self.account()
        return self._request(action, values, mutation=mutation)

    @staticmethod
    def _download_url(url: str):
        u = urlparse(url)
        if u.scheme != "https" or u.username or u.password or u.port not in (None, 443):
            raise AdapterError("UNSAFE_DOWNLOAD_URL", "Output download URL is not an allowed HTTPS resource.")
        host = (u.hostname or "").lower()
        allowed = host in {"www.kaggle.com", "api.kaggle.com", "storage.googleapis.com", "kaggleusercontent.com"} or host.endswith(".kaggleusercontent.com") or host.endswith(".storage.googleapis.com")
        if not allowed:
            raise AdapterError("UNSAFE_DOWNLOAD_HOST", "Kaggle output URL uses an unapproved storage hostname.")

    def download(self, url: str, path: Path, *, expected_size: int | None, max_bytes: int, require_content_length: bool = False) -> dict:
        """Anonymous streaming download; signed URLs never receive API auth."""
        self._download_url(url)
        op = urllib.request.build_opener(NoRedirect())
        for _ in range(6):
            req = urllib.request.Request(url, headers={"User-Agent": "HeptaRuntime-Kaggle/0.1.7", "Accept-Encoding": "identity"})
            try:
                response = op.open(req, timeout=self.timeout)
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308) and exc.headers.get("Location"):
                    url = urljoin(url, exc.headers["Location"])
                    self._download_url(url)
                    continue
                raise RemoteError("DOWNLOAD_HTTP_ERROR", "Kaggle output download failed.", status=exc.code) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                raise RemoteError("DOWNLOAD_TRANSPORT_ERROR", "Kaggle output download did not complete.") from None
        else:
            raise AdapterError("DOWNLOAD_REDIRECT_LIMIT", "Output download exceeded its redirect limit.")
        size, sha = 0, hashlib.sha256()
        try:
            declared = response.headers.get("Content-Length")
            declared = int(declared) if declared and declared.isdigit() else None
            if require_content_length and declared is None:
                raise AdapterError("HTTP_CONTENT_LENGTH_REQUIRED", "Manifest-verified downloads require an explicit valid HTTP Content-Length.")
            if declared is not None and declared > max_bytes:
                raise AdapterError("ARTIFACT_BUDGET", "Output exceeds the configured byte budget.")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                while True:
                    chunk = response.read(min(1024 * 1024, max_bytes - size + 1))
                    if not chunk: break
                    size += len(chunk)
                    if size > max_bytes:
                        raise AdapterError("ARTIFACT_BUDGET", "Output exceeds the configured byte budget.")
                    f.write(chunk); sha.update(chunk)
                f.flush(); os.fsync(f.fileno())
            if declared is not None and size != declared:
                raise AdapterError("ARTIFACT_LENGTH", "Output does not match HTTP Content-Length.")
            if expected_size is not None and size != expected_size:
                raise AdapterError("ARTIFACT_LENGTH", "Output does not match the required expected file size.")
            return {"bytes": size, "sha256": sha.hexdigest(), "http_content_length": declared,
                    "http_content_length_verified": declared is not None}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RemoteError("DOWNLOAD_TRANSPORT_ERROR", "Kaggle output download did not complete.") from None
        finally:
            response.close()
