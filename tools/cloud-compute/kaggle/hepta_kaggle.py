#!/usr/bin/env python3
"""HeptaRuntime adapter for Kaggle; see README for identity guarantees."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from kaggle_transport import AdapterError, KaggleTransport, SDK_SNAPSHOT, dependency_versions, scrub
from kaggle_jobs import KaggleAdapter, submission_readiness
from tool_contract import VERSION, TOOLS, call_argv


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise AdapterError("INVALID_ARGUMENTS", "CLI arguments are invalid; use --help for the supported interface.")


def main(argv=None):
    p = JsonArgumentParser(description=__doc__)
    p.add_argument("--credentials-file")
    p.add_argument("--expected-username", help="Host-configured account guard applied before business RPCs")
    p.add_argument("--http-timeout", type=int, default=45)
    p.add_argument("--state-dir", type=Path, default=Path.home() / ".local/state/hepta-kaggle")
    s = p.add_subparsers(dest="command", required=True)
    s.add_parser("call", help="Read one JSON tool call from stdin and emit one JSON result")
    c = s.add_parser("capabilities"); c.add_argument("--live", action="store_true")
    s.add_parser("account")
    s.add_parser("quota")
    r = s.add_parser("readiness", help="Read-only authentication and full owned-notebook preflight; does not reserve or submit")
    r.add_argument("--request-id", help="Optional correlation ID only; creates no request record")
    n = s.add_parser("notebooks"); n.add_argument("--page-size", type=int, default=20); n.add_argument("--page-token")
    submit = s.add_parser("submit", help="Create and run one private, bounded notebook; stable request ID prevents local replay")
    submit.add_argument("--request-id", required=True)
    submit.add_argument("--source", type=Path, required=True)
    submit.add_argument("--timeout", type=int, default=300)
    submit.add_argument("--accelerator", default="cpu")
    submit.add_argument("--internet", action="store_true")
    submit.add_argument("--kernel-type", choices=("script", "notebook"), default="script")
    for label in ("dataset", "kernel", "model", "competition"):
        submit.add_argument("--" + label + "-source", action="append", default=[])
    for label in ("status", "resume", "wait", "logs", "artifacts", "cancel", "inspect"):
        cmd = s.add_parser(label); cmd.add_argument("--request-id", required=True)
        if label in ("wait", "cancel"): cmd.add_argument("--wait-seconds", type=int, default=30)
        if label == "logs": cmd.add_argument("--cursor"); cmd.add_argument("--limit", type=int, default=16384)
        if label == "artifacts":
            cmd.add_argument("--max-bytes", type=int, default=1024 ** 3)
            cmd.add_argument("--manifest-name", help="Require and verify this execution-generated SHA-256 manifest")
    try:
        a = p.parse_args(argv)
        if a.command == "call":
            raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024: raise AdapterError("TOOL_CALL_TOO_LARGE", "Tool call exceeds 2 MiB.")
            try: data = json.loads(raw)
            except (ValueError, UnicodeError): raise AdapterError("INVALID_TOOL_CALL", "Tool call must be a JSON object.") from None
            cli = ["--state-dir", str(a.state_dir), "--http-timeout", str(a.http_timeout)]
            if a.credentials_file: cli.extend(["--credentials-file", a.credentials_file])
            if a.expected_username: cli.extend(["--expected-username", a.expected_username])
            a = p.parse_args(cli + call_argv(data))
        transport = KaggleTransport(timeout=a.http_timeout, credentials_file=a.credentials_file, expected_username=a.expected_username)
        if a.command == "capabilities":
            out = {"schema": "hepta-kaggle-capabilities-v1", "provider": "kaggle", "adapter_version": VERSION,
                   "sdk_source_snapshot": SDK_SNAPSHOT, "packages": dependency_versions(),
                   "implemented_actions": list(TOOLS),
                   "batch_submission": True, "interactive_execution": False,
                   "cancel_requires_proven_session_id": True, "automatic_submission_replay": False,
                   "real_execution_acceptance": "must_be_established_by_external_receipts",
                   "expected_username": a.expected_username,
                   "authorization": {"state": "not_checked"}}
            if a.live:
                try: out["authorization"] = transport.account()
                except AdapterError as exc: out["authorization"] = {"authenticated": False, "error": exc.as_dict()}
        elif a.command == "account": out = transport.account()
        elif a.command == "readiness": out = submission_readiness(transport, request_id=a.request_id)
        elif a.command == "quota": out = {"account": transport.account(), "raw_quota": transport.call("quota", {})}
        elif a.command == "notebooks":
            if not 1 <= a.page_size <= 200: raise AdapterError("INVALID_PAGE_SIZE", "Page size must be 1..200.")
            vals = {"group": "PROFILE", "user": transport.account()["username"], "page_size": a.page_size}
            if a.page_token: vals["page_token"] = a.page_token
            out = {"account": transport.account(), "notebooks": transport.call("list", vals)}
        else:
            adapter = KaggleAdapter(transport, a.state_dir)
            if a.command == "submit":
                out = adapter.submit(request_id=a.request_id, source=a.source, timeout=a.timeout,
                                     accelerator=a.accelerator, internet=a.internet, kernel_type=a.kernel_type,
                                     dataset_sources=a.dataset_source, kernel_sources=a.kernel_source,
                                     model_sources=a.model_source, competition_sources=a.competition_source)
            elif a.command == "status": out = adapter.status(a.request_id)
            elif a.command == "resume": out = adapter.resume(a.request_id)
            elif a.command == "wait": out = adapter.wait(a.request_id, seconds=a.wait_seconds)
            elif a.command == "logs": out = adapter.logs(a.request_id, cursor=a.cursor, limit=a.limit)
            elif a.command == "artifacts": out = adapter.artifacts(a.request_id, max_bytes=a.max_bytes, manifest_name=a.manifest_name)
            elif a.command == "cancel": out = adapter.cancel(a.request_id, wait_seconds=a.wait_seconds)
            else:
                with adapter.ledger.locked(a.request_id):
                    record = adapter.ledger.load(a.request_id)
                    transport._verify_expected_account(record["account"])
                    out = adapter.receipt(record, observation="local_ledger_only")
        print(json.dumps(scrub({"ok": True, "result": out}), ensure_ascii=False))
        if a.command == "readiness" and not out.get("ready"): return 4
        if a.command == "submit" and out.get("submission_state") not in ("ACCEPTED",): return 4
        if a.command == "cancel" and not out.get("remote_stop_confirmed"): return 4
        if a.command in ("status", "wait", "resume") and out.get("remote_state") == "ERROR": return 4
        return 0
    except AdapterError as exc:
        print(json.dumps({"ok": False, "error": exc.as_dict()}, ensure_ascii=False))
        return 3 if exc.code.startswith("AUTH") else 1
    except KeyboardInterrupt:
        print(json.dumps({"ok": False, "error": {"code": "INTERRUPTED", "message": "Local observation stopped; no remote cancellation is implied."}})); return 130
    except Exception as exc:
        print(json.dumps({"ok": False, "error": {"code": "UNEXPECTED_ERROR", "message": "Adapter failed without exposing upstream details.", "type": type(exc).__name__}})); return 1


if __name__ == "__main__":
    sys.exit(main())
