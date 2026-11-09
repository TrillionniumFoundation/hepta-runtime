import io
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kaggle_transport import AdapterError, KaggleTransport, NoRedirect, RemoteError, MAX_ERROR_BYTES, remember_secret, safe_http_error_diagnostics, scrub


class Reply(io.BytesIO):
    def __init__(self, body, length=None):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body) if length is None else length)}


class TransportTest(unittest.TestCase):
    def test_jwe_in_storage_url_path_is_entirely_redacted(self):
        jwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..aW5pdGlhbHZlY3Rvcg.Y2lwaGVydGV4dA.dGFn"
        url = "https://www.kaggleusercontent.com/kf/366547357/" + jwe + "/result.json"
        public = json.dumps(scrub({"files": [{"url": url}], "log": "Download: " + url}))
        self.assertIn("https://www.kaggleusercontent.com/[REDACTED_STORAGE_URL]", public)
        for secret in (jwe, "366547357", "aW5pdGlhbHZlY3Rvcg", "Y2lwaGVydGV4dA", "/result.json"):
            self.assertNotIn(secret, public)

    def test_storage_paths_and_queries_are_redacted_without_relying_on_token_shape(self):
        for host in ("storage.googleapis.com", "bucket.storage.googleapis.com", "storage.cloud.google.com", "kaggleusercontent.com"):
            url = "https://" + host + "/private/OPAQUE_PATH_CAPABILITY/output.bin?signature=QUERY_SECRET"
            result = scrub(url)
            self.assertEqual(result, "https://" + host + "/[REDACTED_STORAGE_URL]")

    def test_download_keeps_raw_path_capability_only_for_internal_request(self):
        with tempfile.TemporaryDirectory() as d:
            url = "https://www.kaggleusercontent.com/kf/123/OPAQUE_PATH_CAPABILITY/result.json"
            opener = mock.Mock(); opener.open.return_value = Reply(b"abc")
            with mock.patch("urllib.request.build_opener", return_value=opener):
                info = KaggleTransport().download(url, Path(d) / "out", expected_size=3, max_bytes=20)
            self.assertEqual(opener.open.call_args.args[0].full_url, url)
            self.assertEqual(info["bytes"], 3)
            self.assertNotIn("OPAQUE_PATH_CAPABILITY", scrub(url))

    def rpc_error(self, payload, *, raw=None, mutation=True):
        data = raw if raw is not None else json.dumps(payload).encode()
        t = KaggleTransport()
        error = urllib.error.HTTPError("https://api.kaggle.com/private?token=URL_SECRET", 403, "EXCEPTION_SECRET",
                                       {"Authorization": "Bearer HEADER_SECRET", "Set-Cookie": "COOKIE_SECRET"}, io.BytesIO(data))
        t.opener = mock.Mock(); t.opener.open.side_effect = error
        with mock.patch("kaggle_transport.sdk_payload", return_value={}), self.assertRaises(RemoteError) as ctx:
            t._request("submit", {}, mutation=mutation)
        return ctx.exception

    def test_permission_diagnostic_excludes_secrets_echoed_in_body_headers_and_url(self):
        secret = "ACTUAL_TOKEN_SECRET_12345"; remember_secret(secret)
        payload = {"error": {"code": 403, "status": "PERMISSION_DENIED",
                             "message": "Required permission 'kernelSourceReferences.get' was not satisfied",
                             "details": {"token": secret, "url": "https://private.invalid/capability?token=" + secret}},
                   "authorization": secret, "body_debug": "BODY_SECRET"}
        exc = self.rpc_error(payload)
        details = exc.as_dict()["details"]
        self.assertEqual(details, {"rpc_action": "submit", "api_error_code": 403, "api_error_status": "PERMISSION_DENIED",
                                   "required_permission": "kernelSourceReferences.get", "http_status": 403, "remote_effect_unknown": True})
        public = json.dumps(exc.as_dict())
        for value in (secret, "URL_SECRET", "EXCEPTION_SECRET", "HEADER_SECRET", "COOKIE_SECRET", "BODY_SECRET", "https://"):
            self.assertNotIn(value, public)
        self.assertEqual(exc.status, 403); self.assertTrue(exc.ambiguous)

    def test_read_only_403_does_not_claim_a_mutating_request_was_sent(self):
        exc = self.rpc_error({"error": {"code": 403}}, mutation=False)
        self.assertFalse(exc.ambiguous)
        self.assertFalse(exc.as_dict()["details"]["remote_effect_unknown"])

    def test_expected_account_checked_before_any_business_rpc(self):
        t = KaggleTransport(expected_username="expected")
        t._loaded = True; t.token = "placeholder-token"
        t._request = mock.Mock(return_value={"active": True, "username": "other", "userId": 77})
        with self.assertRaises(AdapterError) as ctx: t.call("list", {})
        self.assertEqual(ctx.exception.code, "AUTH_ACCOUNT_MISMATCH")
        self.assertEqual([x.args[0] for x in t._request.call_args_list], ["introspect"])

    def test_expected_account_guard_applies_to_cached_identity(self):
        t = KaggleTransport(expected_username="expected")
        t._account = {"authenticated": True, "username": "other"}
        t._request = mock.Mock()
        with self.assertRaises(AdapterError): t.call("cancel", {"kernel_session_id": 123}, mutation=True)
        t._request.assert_not_called()

    def test_expected_account_guard_does_not_break_matching_account(self):
        t = KaggleTransport(expected_username="expected")
        t._loaded = True; t.token = "placeholder-token"
        t._request = mock.Mock(side_effect=[{"active": True, "username": "expected", "userId": 77}, {}])
        self.assertEqual(t.call("quota", {}), {})
        self.assertEqual([x.args[0] for x in t._request.call_args_list], ["introspect", "quota"])

    def test_legacy_wrong_expected_account_stops_before_quota_probe(self):
        t = KaggleTransport(expected_username="expected")
        t._loaded = True; t.basic = ("other", "placeholder-secret")
        t._request = mock.Mock()
        with self.assertRaises(AdapterError): t.account()
        t._request.assert_not_called()

    def test_denied_permission_is_distinct_from_missing_required_permission(self):
        exc = self.rpc_error({"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "Permission 'kernels.get' was denied"}})
        details = exc.as_dict()["details"]
        self.assertEqual(details["denied_permission"], "kernels.get")
        self.assertNotIn("required_permission", details)

    def test_secret_suffix_and_non_whitelisted_status_are_not_extracted(self):
        exc = self.rpc_error({"error": {"code": "NUMERIC_SECRET", "status": "STATUS_SECRET",
                                       "message": "Required permission 'users.get' was not satisfied token=MESSAGE_SECRET"}})
        details = exc.as_dict()["details"]
        self.assertEqual(set(details), {"rpc_action", "http_status", "remote_effect_unknown"})
        for value in ("NUMERIC_SECRET", "STATUS_SECRET", "MESSAGE_SECRET"): self.assertNotIn(value, json.dumps(exc.as_dict()))

    def test_secret_disguised_as_permission_is_rejected(self):
        secret = "knownCredential.get"; remember_secret(secret)
        exc = self.rpc_error({"error": {"message": "Required permission '" + secret + "' was not satisfied"}})
        self.assertNotIn("required_permission", exc.as_dict()["details"])
        self.assertNotIn(secret, json.dumps(exc.as_dict()))

    def test_error_read_is_bounded_to_64_kib(self):
        class Bounded(io.BytesIO):
            def read(self, size=-1):
                self.assert_size = size
                return super().read(size)
        response = Bounded(b"x" * (MAX_ERROR_BYTES + 100))
        result = safe_http_error_diagnostics(response, "submit")
        self.assertEqual(response.assert_size, MAX_ERROR_BYTES)
        self.assertEqual(result, {"rpc_action": "submit"})

    def test_html_error_does_not_leak_upstream_body(self):
        exc = self.rpc_error({}, raw=b"<html>COOKIE_SECRET token=HTML_SECRET</html>")
        self.assertNotIn("HTML_SECRET", json.dumps(exc.as_dict()))
        self.assertNotIn("COOKIE_SECRET", json.dumps(exc.as_dict()))

    def test_download_never_sends_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            t = KaggleTransport(); t.token = "SUPERSECRET"
            opener = mock.Mock(); opener.open.return_value = Reply(b"abc")
            with mock.patch("urllib.request.build_opener", return_value=opener):
                t.download("https://storage.googleapis.com/bucket/output?signature=secret", Path(d) / "out", expected_size=3, max_bytes=20)
            req = opener.open.call_args.args[0]
            self.assertNotIn("Authorization", dict(req.header_items()))
            self.assertNotIn("Cookie", dict(req.header_items()))

    def test_redirect_cannot_escape_storage_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            t = KaggleTransport()
            opener = mock.Mock()
            opener.open.side_effect = urllib.error.HTTPError("https://storage.googleapis.com/o", 302, "redirect", {"Location": "https://attacker.invalid/capture"}, None)
            with mock.patch("urllib.request.build_opener", return_value=opener), self.assertRaises(AdapterError) as ctx:
                t.download("https://storage.googleapis.com/o", Path(d) / "out", expected_size=None, max_bytes=20)
            self.assertEqual(ctx.exception.code, "UNSAFE_DOWNLOAD_HOST")
            self.assertEqual(opener.open.call_count, 1)

    def test_partial_content_length_is_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            opener = mock.Mock(); opener.open.return_value = Reply(b"abc", length=100)
            with mock.patch("urllib.request.build_opener", return_value=opener), self.assertRaises(AdapterError) as ctx:
                KaggleTransport().download("https://storage.googleapis.com/o", Path(d) / "out", expected_size=None, max_bytes=200)
            self.assertEqual(ctx.exception.code, "ARTIFACT_LENGTH")

    def test_required_http_content_length_must_be_present(self):
        with tempfile.TemporaryDirectory() as d:
            reply = Reply(b"abc"); reply.headers = {}
            opener = mock.Mock(); opener.open.return_value = reply
            with mock.patch("urllib.request.build_opener", return_value=opener), self.assertRaises(AdapterError) as ctx:
                KaggleTransport().download("https://storage.googleapis.com/o", Path(d) / "out", expected_size=None, max_bytes=20,
                                           require_content_length=True)
            self.assertEqual(ctx.exception.code, "HTTP_CONTENT_LENGTH_REQUIRED")

    def test_download_receipt_records_verified_http_size(self):
        with tempfile.TemporaryDirectory() as d:
            opener = mock.Mock(); opener.open.return_value = Reply(b"abc")
            with mock.patch("urllib.request.build_opener", return_value=opener):
                result = KaggleTransport().download("https://storage.googleapis.com/o", Path(d) / "out", expected_size=3, max_bytes=20,
                                                   require_content_length=True)
            self.assertEqual(result["http_content_length"], 3)
            self.assertTrue(result["http_content_length_verified"])

    def test_api_redirect_has_no_follow_request(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://attacker.invalid"))

    def test_url_rejects_cleartext_userinfo_and_hostname_suffix_spoofing(self):
        for url in ("http://storage.googleapis.com/o", "https://user:pass@storage.googleapis.com/o", "https://storage.googleapis.com.attacker.invalid/o", "https://127.0.0.1/o", "https://storage.googleapis.com:8443/o"):
            with self.subTest(url=url), self.assertRaises(AdapterError): KaggleTransport._download_url(url)


if __name__ == "__main__": unittest.main()
