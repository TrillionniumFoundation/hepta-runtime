#!/usr/bin/env python3
"""Finish only the unexecuted native qualification suffix after a typed-error harness failure.

The original attempt remains FAIL_OR_INCOMPLETE. Its 22 complete forwards and
six preparations are reused, never replayed. This is a separately sealed
continuation with cumulative operation/model caps and a tighter 120-second
cumulative active-run wall cap. Review downtime is reported separately.
"""
import argparse
from pathlib import Path
import time
import late_quote_mcp_relocated as m

t = m.t
require, read, parse, digest = m.require, m.read, m.parse, m.digest
MAIN_SHA = "9763f0c078a46c7367703bb7d072003fe2136cf6e5f59656f7733e6f90ac40e9"
PRIOR_PLAN_SHA = "3e145469d1da17d9f92a2d95183d8a1119a12719de2eb1d5a22ee9d38fb65fc8"
PRIOR_RESULT_SHA = "4cbf5fc0c624f944c53caf2cf12ffd0398d20f6df4e046f210d1b81404ca7713"
PRIOR_RESPONSE_SHA = "b6549b634395e5c5bdf085d8b4cb7f9b464920665268081ff36d4914a87c0bc0"
PRIOR_RAW_SHA = "e5573cf4b11feac806d9e6c4c898edd8e02e917dc5b4e72df55fa54b578975e0"
REFUSAL = "failed to deserialize parameters: data did not match any variant of untagged enum SessionWeightRequest"
SCHEMA = "hepta.late-quote.http-continuation-qualification.v1"
PRIOR_COUNTS = {"server_starts":1,"rpc_wire_calls":19,"tool_calls":17,
    "roundtrip_wire_calls":9,"roundtrip_new_intents":3,"recover_wire_calls":0,"crash_attempts":0}
FINAL_COUNTS = {"server_starts":4,"rpc_wire_calls":35,"tool_calls":27,
    "roundtrip_wire_calls":10,"roundtrip_new_intents":4,"recover_wire_calls":6,"crash_attempts":1}
BUDGET = dict(m.BUDGET)
BUDGET["wall_seconds"] = 120
t.BUDGET = BUDGET


def typed_refusal(response, intent, expected_args, request_id):
    require(response["status"] == 200 and response["content_type"] in
            ("text/event-stream", "application/json"), "unexpected refusal HTTP envelope")
    raw = response["raw_utf8"].encode("utf-8")
    require(len(raw) <= t.MAX_WIRE and digest(raw) == response["raw_sha256"], "refusal raw bytes differ")
    request = intent["request"]
    require(request == {"jsonrpc":"2.0","id":request_id,"method":"tools/call",
            "params":{"name":"rea_model_session_weight","arguments":expected_args}},
            "refusal request differs from exact cross-profile control")
    require(type(request["id"]) is int and intent["token_header_present"] is True
            and intent["transport_session_sha256"] == response["transport_session_sha256"],
            "refusal request/session identity differs")
    text = raw.decode("utf-8")
    if text.lstrip().startswith("{"):
        records = [parse(text)]
    else:
        records, data = [], []
        for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") + [""]:
            if not line:
                joined = "\n".join(data)
                if joined:
                    records.append(parse(joined))
                data = []
            elif line == "data" or line.startswith("data:"):
                part = "" if line == "data" else line[5:]
                data.append(part[1:] if part.startswith(" ") else part)
    require(len(records) == 1 and isinstance(records[0], dict), "one exact JSON-RPC refusal required")
    value = records[0]
    expected = {"jsonrpc":"2.0","id":request_id,"result":{
        "content":[{"type":"text","text":REFUSAL}],"isError":True}}
    require(type(value.get("id")) is int and value == expected, "not the specific typed-schema refusal")
    return {"raw_sha256":digest(raw),"request_id":request_id,"message":REFUSAL,
            "tool_is_error":True,"jsonrpc_protocol_error":False,"request_replayed_by_check":False}


def wrong_profile(case, sid):
    args = m.arguments(case, sid, {"kind":"late_quote_compile","request":case["request"]})
    args["profile"] = "smallhcsn_centered_sender_drive_and_bias40_v1"
    return args


def prior(path):
    raw = read(path, private=True)
    require(digest(raw) == PRIOR_PLAN_SHA, "original plan differs")
    v = parse(raw)
    root = Path(v["root"])
    m.private_dir(root)
    require(path == root/"plan.json" and v["schema"] == m.SCHEMA and v["budget"] == m.BUDGET,
            "wrong original sealed protocol")
    require(digest(read(Path(m.__file__).resolve())) == MAIN_SHA == v["driver_sha256"]
            and digest(read(Path(t.__file__).resolve())) == m.TRANSPORT_SHA,
            "reviewed original source differs")
    require(t.package_check(v["binary"], v["package_manifest"], m.SOURCE_COMMIT, m.SOURCE_TREE)
            == v["identity"] and m.ci_check(Path(v["ci"]["path"])) == v["ci"], "qualified binary or CI differs")
    require(digest(read(root/"policy.json", private=True)) == v["policy_sha256"], "original policy differs")
    _, index = m.checked_input_index(Path(v["input_index_path"]))
    require(v["input_index_sha256"] == m.INPUT_INDEX_SHA, "original input index differs")
    for name in ("workspace","state","credentials","evidence"):
        m.private_dir(root/name)
    tokens = {k:read(root/"credentials"/("operator-"+k+".token"), private=True).decode("ascii")
              for k in ("a","b")}
    require(tokens["a"] != tokens["b"] and all(len(s)==64 and all(c in "0123456789abcdef" for c in s)
            for s in tokens.values()), "original credential files differ in shape")
    cases = {}
    require(set(v["cases"]) == {"47","83","137","crash137"}, "original case set differs")
    for name, pin in v["cases"].items():
        require(Path(pin["path"]) == root/"evidence"/("case-"+name+".json"), "original case path escaped")
        body = read(pin["path"], private=True)
        require(digest(body) == pin["sha256"], "original case bytes changed")
        case = parse(body)
        m.verify_case_inputs(case, index, name if name in m.PARENT else "137")
        require(Path(case["source_path"]) == root/"workspace"/(name+".safetensors")
                and digest(read(case["source_path"], private=True)) == m.PARENT[case["seed"]],
                "original unreplayed source differs")
        cases[name] = case
    result_raw = read(root/"evidence/RESULT.json", 4*1024**2, private=True)
    require(digest(result_raw) == PRIOR_RESULT_SHA, "original failure receipt differs")
    result = parse(result_raw)
    require(result["schema"] == m.SCHEMA+".result" and result["status"] == "FAIL_OR_INCOMPLETE"
            and result["failure"] == {"type":"ValueError","message":"cross-profile schema unexpectedly admitted"}
            and result["cleanup_errors"] == [] and result["counts"] == PRIOR_COUNTS
            and result["complete_forward_results_observed"] == 22 and set(result["receipts"]) == {"47","83","137"}
            and result["identity"] == v["identity"] and result["plan_sha256"] == PRIOR_PLAN_SHA,
            "not the exact stopped original attempt")
    require(result["optimizer_steps"] == result["training_steps"] == 0, "original work scope differs")
    require(len(v["ports"]) == 4 and len(set(v["ports"])) == 4, "original port set differs")
    for seed, item in result["receipts"].items():
        require(m.verified_result(root, cases[seed], item["prepared"], item["roundtrip"], v["identity"])
                == item["checks"], "completed original result no longer verifies")
        require(len(item["repeat_roundtrips"]) == 2 and item["cost"]["pure_compiler_invocations"] == 2,
                "original repeated-work evidence omitted")
        for repeated in item["repeat_roundtrips"]:
            require(repeated["new_complete_forward_results_this_request"] == 0
                    and repeated["pure_compiler_invocations_this_request"] == 0
                    and repeated["reused_original_result"] is True, "prior replay charged model work")
            m.inverse(root, cases[seed], item["prepared"], repeated)
    response_raw = read(root/"evidence/a-first-main-019-response.json", private=True)
    require(digest(response_raw) == PRIOR_RESPONSE_SHA, "original refusal response changed")
    response = parse(response_raw)
    require(response["raw_sha256"] == PRIOR_RAW_SHA, "original raw refusal differs")
    typed_refusal(response, parse(read(root/"evidence/a-first-main-019-intent.json", private=True)),
                  wrong_profile(cases["47"], result["receipts"]["47"]["session_id"]), 19)
    require(not (root/"evidence/crash137-prepare.json").exists()
            and not (root/"evidence/crash-boundary.json").exists(), "unexecuted suffix already started")
    return v, root, tokens, cases, result


def plan(args):
    v, root, _, _, result = prior(Path(args.primary_plan))
    snapshot = m.effects(root)
    snap = root/"evidence/CONTINUATION_INITIAL_MODEL_EFFECTS.json"
    value = {"schema":SCHEMA,"primary_plan":str(Path(args.primary_plan)),
        "original_plan_sha256":PRIOR_PLAN_SHA,"original_result_sha256":PRIOR_RESULT_SHA,
        "original_refusal_sha256":PRIOR_RESPONSE_SHA,"driver_sha256":digest(read(Path(__file__).resolve())),
        "original_main_driver_sha256":MAIN_SHA,"transport_sha256":m.TRANSPORT_SHA,
        "initial_effects":{"path":str(snap),"sha256":t.write_once(snap, snapshot)},
        "budget":BUDGET,"prior_counts":PRIOR_COUNTS,"required_final_counts":FINAL_COUNTS,
        "prior_complete_forwards":22,"maximum_new_complete_or_partial_forwards":7,
        "prior_pure_compilers":6,"maximum_new_pure_compilers":2,
        "prior_active_wall_seconds":result["wall_seconds"],"automatic_retry":False,
        "original_failure_preserved":True,"original_negative_effect_snapshot_available":False}
    target = root/"continuation-plan-v1.json"
    print(t.json.dumps({"plan":str(target),"sha256":t.write_once(target,value),"model_forwards":0}))


def run(args):
    body = read(args.plan, private=True)
    p = parse(body)
    require(p["schema"] == SCHEMA and p["budget"] == BUDGET and p["driver_sha256"]
            == digest(read(Path(__file__).resolve())) and p["original_plan_sha256"] == PRIOR_PLAN_SHA
            and p["original_result_sha256"] == PRIOR_RESULT_SHA and p["original_refusal_sha256"] == PRIOR_RESPONSE_SHA,
            "continuation seal differs")
    v, root, tokens, cases, old = prior(Path(p["primary_plan"]))
    require(Path(args.plan) == root/"continuation-plan-v1.json" and p["prior_counts"] == PRIOR_COUNTS
            and p["required_final_counts"] == FINAL_COUNTS and p["prior_active_wall_seconds"] == old["wall_seconds"],
            "continuation original cost or path differs")
    snap = read(p["initial_effects"]["path"], 4*1024**2, private=True)
    require(digest(snap) == p["initial_effects"]["sha256"] and parse(snap) == m.effects(root),
            "model state changed after continuation seal")
    rec = t.Recorder(root, v, tokens)
    rec.counts = dict(PRIOR_COUNTS)
    rec.started -= old["wall_seconds"]
    started = time.monotonic()
    receipts = dict(old["receipts"])
    servers, cleanup = [], []
    status, failure, schema_verified = "FAIL_OR_INCOMPLETE", None, False
    rec.record("continuation-run-intent-v1.json", {"plan_sha256":digest(body),"budget":BUDGET,
        "original_failed_result_sha256":PRIOR_RESULT_SHA,"started_unix_ns":time.time_ns(),"automatic_retry":False})
    def start(label, owner, port):
        server = t.Server(rec,label,owner,port)
        servers.append(server)
        return server
    try:
        case, item = cases["47"], receipts["47"]
        other_server = start("b-other-owner","b",v["ports"][1])
        other = m.Client(other_server,"main")
        before = m.effects(root)
        other.call("rea_model_session_weight",m.recover_args(case,item["session_id"],item["prepared"]),denied=True)
        require(m.effects(root) == before,"foreign owner changed model state")
        rec.record("continuation-foreign-owner-effects.json", {"before":before,"after":m.effects(root)})
        other_server.stop()
        for seed in ("47","83","137"):
            Path(cases[seed]["source_path"]).unlink()
        cold = start("a-cold","a",v["ports"][2])
        client = m.Client(cold,"main")
        before = m.effects(root)
        bad = wrong_profile(case,item["session_id"])
        rec.reserve("tool_calls")
        result = client.rpc("tools/call",{"name":"rea_model_session_weight","arguments":bad})
        label = f"{cold.label}-main-{client.request_id:03d}"
        response = parse(read(rec.evidence_root/(label+"-response.json"),private=True))
        intent = parse(read(rec.evidence_root/(label+"-intent.json"),private=True))
        check = typed_refusal(response,intent,bad,client.request_id)
        require(result == {"content":[{"type":"text","text":REFUSAL}],"isError":True},"decoded refusal differs")
        after = m.effects(root)
        require(before == after,"cross-profile refusal changed model artifacts/journals")
        rec.record("continuation-exact-schema-refusal.json", {"check":check,"before":before,"after":after,
            "model_effects_byte_and_metadata_equal":True,"old_attempt_snapshot_available":False})
        schema_verified = True
        for seed in ("47","83","137"):
            case, item = cases[seed], receipts[seed]
            before = m.effects(root)
            result = m.outer(client.call("rea_model_session_weight",m.recover_args(case,item["session_id"],item["prepared"])))
            require(m.effects(root) == before and result["new_complete_forward_results_this_request"] == 0
                    and result["pure_compiler_invocations_this_request"] == 0 and result["original_source_path_opened"] is False,
                    "cold original recovery performed new work")
            m.inverse(root,case,item["prepared"],result)
            require(not Path(case["source_path"]).exists(),"cold recovery recreated source")
            rec.record("case-"+seed+"-cold-recovery.json",result)
        case = cases["crash137"]
        sid, prepared, pwall = m.open_prepare(client,case,"crash137")
        boundary = m.crash_once(cold,client,case,sid,prepared)
        Path(case["source_path"]).unlink()
        last = start("a-after-kill","a",v["ports"][3])
        client = m.Client(last,"main")
        recovered = m.outer(client.call("rea_model_session_weight",m.recover_args(case,sid,prepared)))
        m.inverse(root,case,prepared,recovered)
        require(recovered["original_source_path_opened"] is False
                and recovered["parent_or_candidate_forward_replayed"] is False
                and recovered["selection_replayed_on_recovery"] is False
                and recovered["pure_compiler_invocations_this_request"] == 0,"crash recovery replayed original work")
        require(recovered["new_complete_forward_results_this_request"] == 2
                and recovered["fresh_restored_complete_outputs_equal"] is True,"fresh inverse forwards absent")
        require(digest(read(m.journal(root,prepared)/"late-intent.json",private=True)) == boundary["intent_sha256"],
                "recovery changed immutable original intent")
        after = m.phases(root,prepared)
        for name,pin in boundary["phase_files"].items():
            if not name.startswith("late-restored-"):
                require(after[name] == pin,"recovery replayed or replaced charged original phases")
        before = m.effects(root)
        second = m.outer(client.call("rea_model_session_weight",m.recover_args(case,sid,prepared)))
        require(m.effects(root) == before and second["new_complete_forward_results_this_request"] == 0
                and second["pure_compiler_invocations_this_request"] == 0,"second crash recovery repeated work")
        m.inverse(root,case,prepared,second)
        require(not Path(case["source_path"]).exists(),"crash source reappeared")
        receipts["crash137"] = {"session_id":sid,"prepared":prepared,"prepare_rpc_wall_seconds":pwall,
            "boundary":boundary,"first_recovery":recovered,"second_recovery":second}
        require(rec.counts == FINAL_COUNTS,"cumulative frozen operation counts differ")
        status = "PASS"
    except BaseException as error:
        failure = {"type":type(error).__name__,"message":str(error)}
    finally:
        for server in reversed(servers):
            try:
                server.stop(kill=status != "PASS")
            except BaseException as error:
                cleanup.append({"server":server.label,"type":type(error).__name__,"message":str(error)})
        try:
            rec.remaining_seconds()
            require(digest(read(root/"evidence/RESULT.json",4*1024**2,private=True)) == PRIOR_RESULT_SHA,
                    "historical failed result was modified")
        except BaseException as error:
            cleanup.append({"stage":"final_bounds_and_original_failure","type":type(error).__name__,"message":str(error)})
        if cleanup:
            status = "FAIL_OR_INCOMPLETE"
        crash = receipts.get("crash137",{}).get("first_recovery")
        complete = 22 + (crash["attempt_ledger"]["completed_forward_calls_with_durable_results"] if crash else 0)
        origin = parse(read(root/"evidence/run-intent.json",private=True))["started_unix_ns"]
        result = {"schema":SCHEMA+".result","status":status,"failure":failure,"cleanup_errors":cleanup,
            "identity":v["identity"],"counts":rec.counts,"budget":BUDGET,"receipts":receipts,
            "continuation_plan_sha256":digest(body),"continuation_driver_sha256":p["driver_sha256"],
            "original_main_driver_sha256":MAIN_SHA,"original_main_plan_sha256":PRIOR_PLAN_SHA,
            "original_failed_main_result_sha256":PRIOR_RESULT_SHA,"original_refusal_response_sha256":PRIOR_RESPONSE_SHA,
            "original_failure_preserved":True,"original_negative_effect_snapshot_available":False,
            "new_schema_refusal_verified":schema_verified,"complete_forward_results_observed":complete,
            "prior_complete_forward_results":22,"actual_total_forward_calls_claimed_exact":False,
            "interrupted_partial_work_accounted_by_original_phase_ledgers":True,
            "forward_source_control_flow_upper_bound":29,"pure_compiler_source_control_flow_upper_bound":8,
            "continuation_new_forward_upper_bound":7,"continuation_new_compiler_upper_bound":2,
            "training_steps":0,"optimizer_steps":0,"automatic_retry":False,"production_deployment":False,
            "continuation_active_wall_seconds":time.monotonic()-started,
            "cumulative_active_wall_seconds":time.monotonic()-rec.started,
            "elapsed_wall_including_review_gap_seconds":(time.time_ns()-origin)/1e9,
            "scope":"composite engineering qualification; original failed attempt preserved, no old model replay"}
        pin = rec.record("CONTINUATION_RESULT_V1.json",result)
        print(t.json.dumps({"status":status,"result":str(rec.evidence_root/"CONTINUATION_RESULT_V1.json"),
                           "sha256":pin,"failure":failure,"cleanup_errors":cleanup}))
    return 0 if status == "PASS" else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action",required=True)
    q = sub.add_parser("plan")
    q.add_argument("--primary-plan",required=True)
    q = sub.add_parser("run")
    q.add_argument("--plan",type=Path,required=True)
    args = p.parse_args()
    return plan(args) if args.action == "plan" else run(args)


if __name__ == "__main__":
    raise SystemExit(main())
