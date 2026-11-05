#!/usr/bin/env python3
"""Actual stdio MCP tests of fresh input errors, retry rejection and revalidation."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import resource
import shutil
import struct
import subprocess
import threading
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


class Mcp:
    def __init__(self, binary, config, log):
        self.log = log.open("xb")
        env = os.environ.copy()
        env.update(CUDA_VISIBLE_DEVICES="", HIP_VISIBLE_DEVICES="", ROCR_VISIBLE_DEVICES="")
        self.process = subprocess.Popen([str(binary), "mcp", "--runtime-config", str(config)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True, bufsize=1, env=env)
        self.sequence = 0
        self.lines = queue.Queue()

        def read():
            for line in self.process.stdout:
                self.lines.put(line)
            self.lines.put(None)

        threading.Thread(target=read, daemon=True).start()
        try:
            self.request("initialize", {"protocolVersion":"2026-07-28", "capabilities":{},
                "clientInfo":{"name":"guard-journal-contract-qualification", "version":"2"}})
            self.send({"jsonrpc":"2.0", "method":"notifications/initialized", "params":{}})
        except BaseException:
            self.close()
            raise

    def send(self, request):
        self.process.stdin.write(json.dumps(request, separators=(",",":"), allow_nan=False)+"\n")
        self.process.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        sequence = self.sequence
        self.send({"jsonrpc":"2.0", "id":sequence, "method":method, "params":params})
        deadline = time.monotonic() + 120
        for _ in range(64):
            line = self.lines.get(timeout=max(.001, deadline-time.monotonic()))
            if line is None:
                raise RuntimeError("runtime ended before MCP response")
            result = json.loads(line)
            if result.get("id") == sequence:
                if "error" in result:
                    raise RuntimeError("unexpected JSON-RPC error: "+str(result["error"]))
                return result["result"]
        raise RuntimeError("MCP notification limit exceeded")

    def call_raw(self, params):
        return self.request("tools/call", {"name":"weight_guarded_linear_patch", "arguments":params})

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


def decode(response):
    assert response.get("isError") is not True, "unexpected tool error"
    return json.loads(response["content"][0]["text"])


def fixture_bytes():
    data = struct.pack("<ff", 1., -3.)
    header = json.dumps({"weight":{"dtype":"F32","shape":[1,2],"data_offsets":[0,len(data)]}}, separators=(",",":")).encode()
    header += b" " * (-len(header) % 8)
    return struct.pack("<Q",len(header)) + header + data


def parameters(path, original):
    return {"patch":{"path":str(path),"expected_sha256":sha(original),"tensor_name":"weight",
        "edits":[{"index":0,"expected_hex":struct.pack("<f",1.).hex(),"replacement_hex":struct.pack("<f",2.).hex()}]},
        "inputs":[[-2.,1.],[.5,2.],[3.,-1.]],"bias":None,
        "objective":{"kind":"squared_error","targets":[[-7.],[-5.],[9.]]},
        "minimum_gain":0.,"constraints":[],"max_update_l2_norm":1.}


def main():
    parser = argparse.ArgumentParser()
    for name in ["binary","work-dir","output","protocol"]:
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--binary-sha256",required=True)
    parser.add_argument("--protocol-sha256",required=True)
    args = parser.parse_args()
    started, cpu = time.perf_counter(), time.process_time()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    os.umask(0o077)
    work=args.work_dir.resolve()
    work.mkdir(mode=0o700,parents=True,exist_ok=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    assert not args.output.exists()
    state=work/"state"
    state.mkdir(mode=0o700)
    raw=[]
    summary={"schema":"hepta.guard-journal-real-mcp-qualification.v2",
        "driver_sha256":file_sha(Path(__file__)),"protocol_sha256":file_sha(args.protocol),
        "started_utc":datetime.now(timezone.utc).isoformat(),"binary_sha256":args.binary_sha256,
        "negative_cases":[],"positive":None,"accepted_artifact_tamper":None,
        "tools_call_count":0,"passed":False,"complete":False,"failure":None,
        "production_eligible":False,"model_efficacy_qualified":False,"sigkill_qualification_in_this_driver":False,
        "scope":"Real MCP contract/current-content authentication using isolated synthetic files",
        "cost_excludes":["compilation","previous_aborted_attempt","source_development","transfer","agent_usage","energy"]}
    mcp=None
    pinned=work/"hepta-runtime-executed"
    pinned_stamp=None

    def save():
        encoded=json.dumps(summary,indent=2,sort_keys=True,allow_nan=False)+"\n"
        assert "/home/" not in encoded and "/Users/" not in encoded
        args.output.write_text(encoded)
        (work/"raw-responses.json").write_text(json.dumps(raw,indent=2,allow_nan=False)+"\n")

    def call(params):
        response=mcp.call_raw(params)
        summary["tools_call_count"] += 1
        raw.append(response)
        return response

    def artifacts():
        directory=state/"weight-artifacts-v1"
        return sorted(p.name for p in directory.glob("wa1_*")) if directory.exists() else []

    current="binary_binding"
    try:
        assert file_sha(args.protocol)==args.protocol_sha256
        assert file_sha(args.binary)==args.binary_sha256
        with args.binary.open("rb") as src, pinned.open("xb") as dst:
            shutil.copyfileobj(src,dst,1024*1024)
        pinned.chmod(0o500)
        assert file_sha(pinned)==args.binary_sha256
        pinned_stamp=pinned.stat()
        config=work/"runtime.json"
        config.write_text(json.dumps({"state_dir":str(state),"controller_workspace_roots":[str(work)],
            "weight_workers":{},"hosts":{"unused":{"ssh_target":"unused.invalid",
                "remote_state_dir":str(work/"unused"),"allow_execute":False}}}))
        mcp=Mcp(pinned,config,work/"mcp.stderr.log")
        original=fixture_bytes()
        summary["synthetic_parent_sha256"]=sha(original)
        expected_reasons={
            "over_budget":"exact joint L2 update budget",
            "forged_old_bytes":"does not match its exact expected bytes",
            "duplicate_address":"tensor edit index is out of range or repeated",
            "bad_labels":"evaluation labels must be finite and exactly match rows and objective columns",
        }
        for name in ["over_budget","forged_old_bytes","duplicate_address","bad_labels"]:
            current=name
            source=work/(name+".safetensors")
            source.write_bytes(original)
            params=parameters(source,original)
            if name=="over_budget": params["max_update_l2_norm"]=.5
            elif name=="forged_old_bytes":
                params["patch"]["edits"][0]["expected_hex"]=struct.pack("<f",0.).hex()
                params["max_update_l2_norm"]=10.
            elif name=="duplicate_address":
                params["patch"]["edits"].append(copy.deepcopy(params["patch"]["edits"][0]))
                params["max_update_l2_norm"]=10.
            elif name=="bad_labels": params["objective"]["targets"]=[]
            start=time.perf_counter()
            fresh=call(params)
            assert fresh.get("isError") is True, name+" fresh request lost MCP isError"
            message="\n".join(block.get("text","") for block in fresh.get("content",[]))
            assert "fresh guarded request rejected" in message
            assert expected_reasons[name] in message, name+" rejected for an unexpected reason"
            fresh_wall=time.perf_counter()-start
            assert not artifacts()
            retry=decode(call(params))
            assert retry["accepted"] is False and retry["outcome"]=="rejected_recovery_unverified"
            assert retry["interruption_recovery_verified"] is False
            assert expected_reasons[name] in retry["error"]
            assert not artifacts() and source.read_bytes()==original
            summary["negative_cases"].append({"case":name,"fresh_mcp_is_error":True,
                "fresh_original_reason_retained":True,"fresh_error_sha256":sha(message.encode()),
                "expected_reason_family":expected_reasons[name],
                "fresh_error_sanitized":message.replace(str(work),"<WORK>")[:2048],
                "fresh_call_wall_seconds":fresh_wall,"retry_accepted":False,
                "retry_outcome":retry["outcome"],"retry_recovery_verified":False,
                "completed_artifacts_published":0,"source_bytes_unchanged":True})
            save()
        current="positive_and_completed_revalidation"
        source=work/"positive.safetensors"
        source.write_bytes(original)
        params=parameters(source,original)
        accepted=decode(call(params))
        assert accepted["accepted"] is True and accepted["durable_evaluation_receipt"] is True
        expected_fields={"candidate","accepted","primary_before","primary_after","gain",
            "candidate_constraint_violations","parent_constraint_violations","f32_update_budget"}
        assert expected_fields.issubset(accepted)
        assert accepted["f32_update_budget_source_bytes_authenticated"] is True
        repeated=decode(call(params))
        assert repeated["accepted"] is True
        assert repeated["completed_receipt_reauthenticated_by_full_guard_replay"] is True
        assert repeated["candidate"]["artifact_id"]==accepted["candidate"]["artifact_id"]
        assert len(artifacts())==1
        summary["positive"]={"accepted":True,"top_level_contract_preserved":True,
            "durable_completion":True,"completed_retry_full_guard_revalidation":True,
            "candidate_full_sha256":accepted["candidate"]["sha256"],"artifact_count":1}
        current="accepted_artifact_tamper"
        target=Path(accepted["candidate"]["artifact_path"]).resolve()
        assert target.is_relative_to(state.resolve())
        changed=bytearray(target.read_bytes())
        changed[-1]^=1
        target.write_bytes(changed)
        rejected=decode(call(params))
        assert rejected["accepted"] is False and rejected["interruption_recovery_verified"] is False
        assert rejected["current_durable_completion"] is False
        assert source.read_bytes()==original
        summary["accepted_artifact_tamper"]={"accepted":False,"recovery_verified":False,
            "cached_acceptance_used":False,"outcome":rejected["outcome"],"parent_unchanged":True}
        summary["complete"]=True
        summary["passed"]=(summary["tools_call_count"]==11 and len(summary["negative_cases"])==4)
    except BaseException as error:
        summary["failure"]={"phase":current,"type":type(error).__name__,
            "message":str(error).replace(str(work),"<WORK>").replace(str(args.binary.resolve()),"<BINARY>")[:2048]}
    finally:
        if mcp is not None: mcp.close()
        if pinned_stamp is not None:
            now=pinned.stat()
            fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")
            unchanged=(tuple(getattr(now,x) for x in fields)==tuple(getattr(pinned_stamp,x) for x in fields)
                and file_sha(pinned)==args.binary_sha256)
            summary["executed_binary_unchanged"]=unchanged
            summary["passed"] = summary["passed"] and unchanged
        after=resource.getrusage(resource.RUSAGE_CHILDREN)
        summary.update(finished_utc=datetime.now(timezone.utc).isoformat(),
            driver_wall_seconds=time.perf_counter()-started,driver_cpu_seconds=time.process_time()-cpu,
            child_user_cpu_seconds=after.ru_utime-before.ru_utime,
            child_system_cpu_seconds=after.ru_stime-before.ru_stime,
            child_max_rss_kib=after.ru_maxrss,
            child_max_rss_scope="maximum waited-for child high-water mark, not aggregate concurrent memory")
        if (work/"mcp.stderr.log").exists(): summary["private_stderr_sha256"]=file_sha(work/"mcp.stderr.log")
        summary["private_raw_responses_published"]=False
        summary["driver_source_unchanged"]=file_sha(Path(__file__))==summary["driver_sha256"]
        summary["protocol_unchanged"]=file_sha(args.protocol)==summary["protocol_sha256"]
        summary["passed"] = summary["passed"] and summary["driver_source_unchanged"] and summary["protocol_unchanged"]
        save()
    print(json.dumps({"passed":summary["passed"],"tools_call_count":summary["tools_call_count"],
        "receipt_sha256":file_sha(args.output),"driver_wall_seconds":summary["driver_wall_seconds"]}))
    return 0 if summary["passed"] else 2


if __name__=="__main__":
    raise SystemExit(main())
