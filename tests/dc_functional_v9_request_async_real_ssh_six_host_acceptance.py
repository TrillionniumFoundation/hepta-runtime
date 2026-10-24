#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Separate V9 sequential six-host native real-SSH read-only acceptance.

Uses actual configured SSH aliases and the original account SSH authority.
Only the typed fixed host_health challenge is dispatched. Private candidate
controllers never read an installed token or touch installed runtime state.
There is no fake SSH executable, target mutation, job, deployment or replay.

Normal, lost-ACK and cancellation scenarios use three separate explicit keys.
An already completed cancellation race is recorded as missing cancellation
evidence. Real SSH invocation counts and transport delivery before dispatch are
not observable here and are never inferred from an admission state string.
"""
import argparse
import copy
import datetime
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import tempfile
import time
import traceback

import dc_functional_v9_request_async_acceptance as native

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOSTS = ("main", "rog", "pocket4", "ai395", "x230", "mac")
HELPERS = (
    ROOT / "tests/dc_functional_v9_request_async_acceptance.py",
    ROOT / "deploy/mcp_tool_contract.py",
)


def host_report(host, configured, binary, contract, token_values, directory):
    """One host, at most one admitted health operation at a time."""
    out = directory / (host + ".json")
    logs = directory / (host + "-logs")
    logs.mkdir(mode=0o700, exist_ok=False)
    report = {
        "schema": "hepta-v9-request-async-real-ssh-host-v1", "host": host,
        "platform_origin": "administrator_configured_platform",
        "configured_platform": configured["platform"],
        "origin": "private_native_http_controller_real_ssh",
        "actual_ssh": True, "fake_ssh": False,
        "actual_ssh_invocation_count_proven": False,
        "transport_delivery_precedes_dispatch_proven": False,
        "model_origin_qualified": False, "full_dc_replacement_qualified": False,
        "installed_runtime_changed": False, "desktop_commander_changed": False,
        "original_runtime_state_touched": False, "checks": [],
        "actual_read_health_complete": False, "actual_cancel_qualified": False,
        "complete": False, "owned_controller_cleanup_confirmed": False,
    }
    root, controller, current = None, None, "prepare private candidate controller"
    secret_values = []

    def sanitize(text):
        for secret in secret_values:
            text = text.replace(secret, "[redacted-private-fixture-input]")
        return text

    def save():
        out.write_text(sanitize(json.dumps(report, indent=2, ensure_ascii=False) + "\n"))
        out.chmod(0o600)

    def passed(label, detail):
        report["checks"].append({"check":label, "result":"passed", "detail":detail})
        save()

    def fresh_key():
        value = native.secrets.token_hex(32)
        secret_values.append(value)
        return value

    def terminal(client, state, request_id):
        outcome = native.until(lambda: native.local_outcome(state, request_id), seconds=25)
        public = native.settled(client, state, request_id, expected=outcome["state"])
        assert public["owned_future_active"] is False
        assert public["remote_termination_confirmed"] is False
        return public

    def healthy(client, state, request_id):
        public = terminal(client, state, request_id)
        assert public["async_state"] == "completed"
        raw, dto, pages = native.reconstruct(client, state, request_id)
        assert dto["schema"] == "hepta-host-health-v1"
        assert dto["host"] == host and dto["platform"] == configured["platform"]
        assert dto["status"] == "healthy" and dto["reachable"] is True
        assert dto["authenticated"] is True and dto["transport"] == "ssh"
        assert dto["diagnostics_redacted"] is True
        assert dto["timeout_ms"] == 10000
        assert isinstance(dto["ssh_roundtrip_ms"], (int,float))
        assert 0 <= dto["ssh_roundtrip_ms"] <= 60000
        return raw, pages, dto["ssh_roundtrip_ms"]

    save()
    try:
        root = pathlib.Path(tempfile.mkdtemp(prefix="hepta-v9-real-ssh-" + host + "-")).resolve()
        root.chmod(0o700)
        workspace, state = root / "workspace", root / "state"
        workspace.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        token = native.secrets.token_hex(32)
        secret_values.append(token)
        token_values.append(token)
        tokenfile, config = root / "token", root / "runtime.json"
        native.private_write(tokenfile, token)
        private_host = {
            "ssh_target":configured["ssh_target"], "platform":configured["platform"],
            "remote_state_dir":configured["remote_state_dir"],
            "execution_mode":"isolated", "allow_execute":False, "allow_pty":False,
            "allow_write":False, "allow_job_network":False, "allow_detached_fallback":False,
            "allowed_read_path_prefixes":[], "allowed_write_path_prefixes":[],
            "privileged_actions":{},
        }
        private_cfg = {
            "state_dir":str(state), "controller_workspace_roots":[str(workspace)],
            "hosts":{host:private_host},
        }
        native.private_write(config, json.dumps(private_cfg))
        # Preserve original SSH identity/agent/config authority. Only executable
        # resolution is fixed to the independently hashed real system SSH client.
        env = dict(os.environ)
        env["PATH"] = "/usr/bin:/bin"
        env["RUST_LOG"] = "warn"
        controller = native.Controller(binary, workspace, config, tokenfile, env, logs)
        client = controller.start()
        contract.verify(client.rpc("tools/list", {})["tools"])
        report["negotiated_protocol_version"] = client.protocol
        report["original_ssh_authority_preserved"] = True
        report["private_permissions"] = {"execute":False,"pty":False,"write":False,"job_network":False}
        operation = {"tool":"host_health","arguments":{"host":host}}

        current = "normal real health admission and same-credential reconnect result"
        normal_key = fresh_key()
        began = time.monotonic()
        admitted = native.start_request(client, operation, normal_key)
        admission_ms = (time.monotonic() - began) * 1000
        normal_id = admitted["request_id"]
        after_reply = client.call("request_status", {"request_id":normal_id})
        assert after_reply["early_return_async_start_supported"] is True
        reconnect = native.Client(client.url, token)
        original, pages, ssh_ms = healthy(reconnect, state, normal_id)
        retry = native.start_request(reconnect, operation, normal_key)
        assert retry["reused"] is True and retry["request_id"] == normal_id
        repeated, repeated_pages, _ = healthy(reconnect, state, normal_id)
        assert repeated == original and repeated_pages["sha256"] == pages["sha256"]
        passed(current, {
            "admission_received_ms":admission_ms, "receipt_state":admitted["async_state"],
            "post_reply_observed_state":after_reply["async_state"],
            "post_reply_owned_future_active":after_reply["owned_future_active"],
            "ack_state_does_not_prove_network_delivery_before_dispatch":True,
            "same_credential_new_session_original_id_and_bytes":True,
            "original_result":pages, "ssh_roundtrip_ms":ssh_ms,
        })

        current = "lost ACK same-key recovery preserves original identity and immutable real result"
        lost_key = fresh_key()
        journal = state / "request-async-v9"
        prior_names = {path.name for path in journal.glob("*.json")}
        def admitted_without_reading_id():
            def new_primary_exists():
                names = {path.name for path in journal.glob("*.json")} - prior_names
                assert len(names) <= 1
                return bool(names)
            native.until(new_primary_exists, seconds=15)
        lost = native.discard_ack_without_reading(client, operation, lost_key, admitted_without_reading_id)
        recovered_client = native.Client(client.url, token)
        recovered = native.start_request(recovered_client, operation, lost_key)
        assert recovered["reused"] is True
        recovered_id = recovered["request_id"]
        new_paths = [path for path in journal.glob("*.json") if path.name not in prior_names]
        assert len(new_paths) == 1
        assert json.loads(new_paths[0].read_bytes())["request_id"] == recovered_id
        snapshot, lost_pages, lost_ssh_ms = healthy(recovered_client, state, recovered_id)
        repeat = native.start_request(recovered_client, operation, lost_key)
        assert repeat["reused"] is True and repeat["request_id"] == recovered_id
        identical, again_pages, _ = healthy(recovered_client, state, recovered_id)
        assert identical == snapshot and again_pages["sha256"] == lost_pages["sha256"]
        assert {path.name for path in journal.glob("*.json")} - prior_names == {new_paths[0].name}
        passed(current, {
            **lost, "same_generated_inner_id":True, "immutable_bytes_unchanged":True,
            "single_durable_key_binding":True, "original_result":lost_pages,
            "ssh_roundtrip_ms":lost_ssh_ms, "actual_ssh_invocation_count_proven":False,
            "no_dispatch_replay_inferred_from_idempotency_binding_only":True,
        })
        report["actual_read_health_complete"] = True

        current = "one explicit real-host owned-future cancellation attempt"
        # Initialize a separate same-credential session before admission to
        # reduce avoidable local handshake delay without delaying a real host.
        cancel_client = native.Client(client.url, token)
        cancel_key = fresh_key()
        cancel_admission = native.start_request(client, operation, cancel_key)
        cancel_id = cancel_admission["request_id"]
        cancellation = cancel_client.call("request_cancel", {"request_id":cancel_id})
        assert cancellation["request_id"] == cancel_id
        assert cancellation["cancellation_scope"] == "this_controller_owned_rust_future_only"
        assert cancellation["remote_termination_confirmed"] is False
        final = terminal(cancel_client, state, cancel_id)
        accepted = cancellation["cancel_requested"] is True
        cancelled = final["async_state"] in {"cancelled_before_dispatch","cancelled_future"}
        qualified = accepted and cancelled and final["owned_future_active"] is False
        report["cancellation"] = {
            "cancel_requested":cancellation["cancel_requested"],
            "request_observation":cancellation["observation"],
            "terminal_async_state":final["async_state"], "owned_future_active":False,
            "remote_termination_confirmed":False,
            "owned_future_cancel_observed":qualified, "actual_cancel_qualified":False,
            "qualification_rule":"accepted owned future request plus observed cancelled terminal; completion race does not qualify cancellation",
        }
        if qualified:
            assert final["dispatch_state"] == "unknown" and final["result_state"] == "not_completed"
            native.denied(cancel_client, "request_result", {"request_id":cancel_id})
            report["actual_cancel_qualified"] = True
            report["cancellation"]["actual_cancel_qualified"] = True
            passed(current, report["cancellation"])
        else:
            report["checks"].append({"check":current,"result":"missing","detail":report["cancellation"]})
            report["missing"] = ["actual owned-future cancellation not observed before terminal completion"]
            # A completed race may still produce a valid health DTO, but it is
            # never relabelled as a successful cancellation.
            if final["async_state"] == "completed":
                healthy(cancel_client, state, cancel_id)
            save()
    except BaseException as error:
        report["failure"] = {
            "check":current, "type":type(error).__name__, "detail":sanitize(str(error))[:1536],
            "location":[{"function":frame.name,"file":pathlib.Path(frame.filename).name,"line":frame.lineno}
                        for frame in traceback.extract_tb(error.__traceback__)],
        }
    finally:
        try:
            if controller:
                controller.cleanup()
            report["owned_controller_cleanup_confirmed"] = (
                controller is None or all(child.poll() is not None for child in controller.children)
            )
            if root:
                (root / "token").unlink(missing_ok=True)
                # All admitted operations were awaited to a public non-active
                # terminal before normal cleanup. No SSH PID or multiplexing
                # master is guessed or signalled by the acceptance harness.
                if report["owned_controller_cleanup_confirmed"]:
                    shutil.rmtree(root)
                    report["private_candidate_state_removed"] = True
        except BaseException as error:
            report["owned_controller_cleanup_confirmed"] = False
            report["cleanup_failure"] = {"type":type(error).__name__,"detail":sanitize(str(error))[:512]}
            if root:
                (root / "token").unlink(missing_ok=True)
                report["preserved_owned_fixture_path"] = str(root)
        report["logs"] = []
        for path in sorted(logs.glob("*.log")):
            raw = path.read_bytes()
            text = sanitize(raw.decode(errors="replace"))
            text = "".join(
                "[redacted authentication/header line]\n"
                if any(marker in line.lower() for marker in (
                    "x-hepta-runtime-token","authorization:","cookie:","set-cookie:","mcp-session-id",'"headers"',
                )) else line for line in text.splitlines(keepends=True)
            )
            path.write_text(text)
            path.chmod(0o600)
            report["logs"].append({"name":path.name,"sha256":native.digest(path),"bytes":path.stat().st_size})
        report["complete"] = bool(
            report["actual_read_health_complete"] and report["actual_cancel_qualified"] and
            report["owned_controller_cleanup_confirmed"] and "failure" not in report
        )
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",required=True)
    parser.add_argument("--runtime-config",required=True)
    parser.add_argument("--contract",required=True)
    parser.add_argument("--expected-binary-sha256",required=True)
    parser.add_argument("--expected-source-fingerprint",required=True)
    parser.add_argument("--expected-contract-sha256",required=True)
    parser.add_argument("--expected-native-helper-sha256",required=True)
    parser.add_argument("--expected-contract-loader-sha256",required=True)
    parser.add_argument("--receipt-dir",required=True)
    parser.add_argument("--out",required=True)
    parser.add_argument("--host",choices=HOSTS)
    args = parser.parse_args()
    for value in [args.expected_binary_sha256,args.expected_source_fingerprint,args.expected_contract_sha256,
                  args.expected_native_helper_sha256,args.expected_contract_loader_sha256]:
        if re.fullmatch("[0-9a-f]{64}",value) is None:
            parser.error("explicit lowercase SHA256 pins required")
    assert sys.platform.startswith("linux"), "real SSH controller fixture requires Linux controller"
    binary = pathlib.Path(args.binary).resolve(strict=True)
    runtime_path = pathlib.Path(args.runtime_config).resolve(strict=True)
    contract_path = pathlib.Path(args.contract).resolve(strict=True)
    directory = pathlib.Path(args.receipt_dir).resolve()
    output = pathlib.Path(args.out).resolve()
    assert not output.exists(), "never overwrite an earlier matrix receipt"
    directory.mkdir(mode=0o700,exist_ok=False)
    output.parent.mkdir(parents=True,exist_ok=True)
    original_config_sha = native.digest(runtime_path)
    configured = json.loads(runtime_path.read_bytes())
    assert isinstance(configured,dict) and isinstance(configured.get("hosts"),dict)
    selected = (args.host,) if args.host else HOSTS
    assert all(host in configured["hosts"] for host in HOSTS), "six configured aliases are required"
    hosts = {}
    for host in selected:
        candidate = configured["hosts"][host]
        assert all(name in candidate for name in ["ssh_target","platform","remote_state_dir"])
        assert isinstance(candidate["ssh_target"],str) and candidate["ssh_target"].strip()
        assert candidate["platform"] in {"linux","macos"}
        assert isinstance(candidate["remote_state_dir"],str) and candidate["remote_state_dir"].startswith("/")
        hosts[host] = {name:copy.deepcopy(candidate[name]) for name in ["ssh_target","platform","remote_state_dir"]}
    configured = None
    ssh = pathlib.Path("/usr/bin/ssh")
    info = ssh.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
    with ssh.open("rb") as reader:
        assert reader.read(4) == b"\x7fELF", "real system SSH executable required"
    ssh_before = native.digest(ssh)
    source_before = native.source_identity()
    binary_before = native.digest(binary)
    harness_before = native.digest(__file__)
    helpers_before = {path.relative_to(ROOT).as_posix():native.digest(path) for path in HELPERS}
    assert binary_before == args.expected_binary_sha256
    assert source_before["source_code_fingerprint"] == args.expected_source_fingerprint
    assert native.digest(HELPERS[0]) == args.expected_native_helper_sha256
    assert native.digest(HELPERS[1]) == args.expected_contract_loader_sha256
    contract = native.ToolContract.load(contract_path,args.expected_contract_sha256)
    report = {
        "schema":"hepta-v9-request-async-real-ssh-six-hosts-v1",
        "recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "qualification_scope":"sequential native configured six-host real read-only SSH health and owned-future observations",
        "source_before":source_before,"binary_sha256":binary_before,"harness_sha256":harness_before,
        "helper_sha256_before":helpers_before,"contract_sha256":args.expected_contract_sha256,
        "explicit_helper_pins":{"native_harness":args.expected_native_helper_sha256,
                                "contract_loader":args.expected_contract_loader_sha256},
        "original_runtime_config_sha256":original_config_sha,
        "original_config_summary":{"schema":"configured-runtime-hosts-map",
                                   "aliases":list(HOSTS),"selected_aliases":list(selected),
                                   "platforms":{name:entry["platform"] for name,entry in hosts.items()}},
        "real_ssh_executable":{"path":str(ssh),"sha256":ssh_before,"uid":info.st_uid,
                               "mode":stat.S_IMODE(info.st_mode),"elf_verified":True},
        "actual_ssh":True,"fake_ssh":False,"actual_ssh_invocation_count_proven":False,
        "transport_delivery_precedes_dispatch_proven":False,
        "actual_read_health_complete":False,"actual_cancel_all_hosts_qualified":False,
        "selected_complete":False,"complete":False,"results":[],
        "model_origin_qualified":False,"full_dc_replacement_qualified":False,
        "production_recovery_rollback_qualified":False,"authenticated_chatgpt_caller_isolation":False,
        "original_runtime_state_touched":False,"installed_runtime_changed":False,"desktop_commander_changed":False,
        "execution_order":"sequential hosts; one admitted health operation settled before the next explicit key",
        "limits":[
            "Identity and immutable bytes prove receipt recovery; real SSH invocation count is not observed.",
            "A fast completed health race is missing cancellation evidence, not a cancellation pass.",
            "An admission state string does not prove response delivery preceded SSH dispatch.",
            "Only existing configured aliases and SSH authority are exercised; no job, target mutation or deployment.",
            "Popen controller handles are cleaned up; no arbitrary SSH PID or existing multiplexing master is signalled.",
        ],
    }
    private_tokens = []
    def save():
        text = json.dumps(report,indent=2,ensure_ascii=False) + "\n"
        assert all(token not in text for token in private_tokens)
        output.write_text(text)
        output.chmod(0o600)
    save()
    try:
        for host in selected:
            result = host_report(host,hosts[host],binary,contract,private_tokens,directory)
            report["results"].append(result)
            save()
            print("HOST",host,"read_health",result["actual_read_health_complete"],
                  "own_future_cancel",result["actual_cancel_qualified"],flush=True)
    finally:
        after = native.source_identity()
        helpers_after = {path.relative_to(ROOT).as_posix():native.digest(path) for path in HELPERS}
        report["source_after"] = after
        report["helper_sha256_after"] = helpers_after
        report["before_after_stable"] = (
            source_before["source_code_fingerprint"] == after["source_code_fingerprint"] and
            binary_before == native.digest(binary) and harness_before == native.digest(__file__) and
            helpers_before == helpers_after and ssh_before == native.digest(ssh) and
            original_config_sha == native.digest(runtime_path) and
            args.expected_contract_sha256 == native.digest(contract_path)
        )
        rows = report["results"]
        all_six = len(rows) == len(HOSTS) and {row["host"] for row in rows} == set(HOSTS)
        stable = report["before_after_stable"]
        cleanup = len(rows) == len(selected) and all(row["owned_controller_cleanup_confirmed"] for row in rows)
        report["actual_read_health_complete"] = bool(all_six and stable and cleanup and all(row["actual_read_health_complete"] for row in rows))
        report["actual_cancel_all_hosts_qualified"] = bool(all_six and stable and cleanup and all(
            row["actual_cancel_qualified"] and "failure" not in row for row in rows))
        report["selected_read_health_complete"] = bool(len(rows) == len(selected) and stable and cleanup and all(row["actual_read_health_complete"] for row in rows))
        report["selected_complete"] = bool(len(rows) == len(selected) and stable and cleanup and all(row["complete"] for row in rows))
        report["complete"] = bool(all_six and report["selected_complete"] and
                                  report["actual_read_health_complete"] and report["actual_cancel_all_hosts_qualified"])
        report["missing_cancellation_hosts"] = [row["host"] for row in rows if not row["actual_cancel_qualified"]]
        report["owned_controller_cleanup_confirmed"] = cleanup
        save()
    if not report["complete"]:
        raise SystemExit(1)
    print("ALL_PASS_REAL_SSH_NATIVE_SIX_HOST_READ_SCOPE",flush=True)


if __name__ == "__main__":
    main()
