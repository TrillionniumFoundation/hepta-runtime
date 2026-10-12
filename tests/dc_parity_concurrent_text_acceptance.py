#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Adversarial write concurrency, bounded UTF-8 and conflict response tests.

Runs ONLY against a disposable authenticated candidate MCP runtime and private
controller workspace. No ChatGPT-originated writes, production service restarts,
or OS privilege changes. The candidate must have the reviewed v4 50-tool schema.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tests"))
from runtime_http_acceptance import Client
sys.path.insert(0,str(ROOT/"deploy"))
from mcp_tool_contract import ToolContract

def call_once(url, token, name, args, barrier):
    # Each client has an independent native session and an explicit authorization
    # token. Simulate competing callers without sharing a non-thread-safe session.
    client=Client(url,token)
    barrier.wait(timeout=10)
    response=client.rpc("tools/call",{"name":name,"arguments":args})
    blocks=response.get("content") or []
    body=next((x.get("text") for x in blocks if x.get("type")=="text"),"")
    if response.get("isError"): return {"passed":False,"error":body[:150]}
    return {"passed":True,"data":json.loads(body)}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--binary",required=True)
    ap.add_argument("--out",required=True)
    ap.add_argument("--v4-contract",default=str(ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json"))
    ap.add_argument("--waves",type=int,default=6)
    ap.add_argument("--contenders",type=int,default=8)
    args=ap.parse_args()
    assert 1<=args.waves<=20 and 2<=args.contenders<=16
    checks=[]
    def passed(name): checks.append(name);print("PASS",name,flush=True)
    with tempfile.TemporaryDirectory(prefix="hepta-dc-concurrency-") as d:
        base=pathlib.Path(d);workspace=base/"workspace";workspace.mkdir(mode=0o700)
        tokenfile=base/"token";tokenfile.write_text(secrets.token_hex(32));tokenfile.chmod(0o600)
        token=tokenfile.read_text()
        host={'ssh_target':'localhost','platform':'linux','remote_state_dir':str(base/'unused'),
            'execution_mode':'isolated','allow_execute':False,'allow_pty':False,'allow_write':False,
            'allowed_read_path_prefixes':[str(workspace)],'allowed_write_path_prefixes':[str(workspace)]}
        config=base/"runtime.json";config.write_text(json.dumps({
            'state_dir':str(base/'state'),'controller_workspace_roots':[str(workspace)],
            'hosts':{'disabled-fixture':host}}))
        with socket.socket() as soc:
            soc.bind(("127.0.0.1",0));port=soc.getsockname()[1]
        url=f"http://127.0.0.1:{port}/mcp"
        with (base/"runtime.log").open("wb") as log:
            controller=subprocess.Popen([str(pathlib.Path(args.binary).resolve(strict=True)),
                "mcp","--path",str(workspace),"--bind",f"127.0.0.1:{port}",
                "--runtime-config",str(config),"--auth-token-file",str(tokenfile)],
                stdout=log,stderr=log,stdin=subprocess.DEVNULL)
            try:
                for _ in range(150):
                    if controller.poll() is not None:
                        raise RuntimeError("candidate quit: "+(base/"runtime.log").read_text(errors="replace")[-1000:])
                    try: c=Client(url,token);break
                    except (OSError,urllib.error.URLError,RuntimeError):time.sleep(.1)
                else:raise TimeoutError("candidate not ready")
                catalog=c.rpc("tools/list",{})["tools"]
                file=pathlib.Path(args.v4_contract)
                contract=ToolContract.load(file,hashlib.sha256(file.read_bytes()).hexdigest())
                assert len(catalog)==50;contract.verify(catalog)
                passed("isolated native controller exactly matches pinned v4 50-tool catalog")
                target=workspace/"concurrent.txt"
                init=c.call("text_file_write",{"path":str(target),"mode":"create",
                    "expected_sha256":"absent","content":"base\n"})
                previous=init["sha256"]
                for wave in range(args.waves):
                    barrier=threading.Barrier(args.contenders)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=args.contenders) as pool:
                        futures=[pool.submit(call_once,url,token,"text_file_write",{
                            "path":str(target),"mode":"append","expected_sha256":previous,
                            "content":f"wave-{wave} contender-{i} 中文\n"
                        },barrier) for i in range(args.contenders)]
                        responses=[f.result(timeout=40) for f in futures]
                    wins=[x for x in responses if x["passed"]]
                    failures=[x for x in responses if not x["passed"]]
                    assert len(wins)==1,(wave,responses)
                    assert len(failures)==args.contenders-1,(wave,responses)
                    raw=target.read_bytes()
                    assert raw.endswith(b"\n") and b"wave-" in raw
                    digest=hashlib.sha256(raw).hexdigest()
                    assert wins[0]["data"]["sha256"]==digest
                    assert digest!=previous
                    assert sum(f"wave-{wave} contender-{i} 中文\n".encode() in raw for i in range(args.contenders))==1
                    assert all("SHA256 mismatch" in entry["error"] for entry in failures), (wave,failures)
                    previous=digest
                    print("WAVE",wave+1,"WON",1,"REFUSED",len(failures),flush=True)
                passed(f"{args.waves} rounds of {args.contenders} parallel append calls allow exactly one winner")
                debris=list(workspace.glob(".hepta-text-*"))
                assert not debris,debris
                passed("all failed contenders leave no orphan staging files")
                # Create-only is an independent competition: the first writer
                # publishes and every other caller must lose without changing
                # the winning bytes or replacing the inode.
                fresh=workspace/"competing-create.txt"
                barrier=threading.Barrier(args.contenders)
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.contenders) as pool:
                    futures=[pool.submit(call_once,url,token,"text_file_write",{
                        "path":str(fresh),"mode":"create","expected_sha256":"absent",
                        "content":f"unique-create-writer-{i}\n"
                    },barrier) for i in range(args.contenders)]
                    creations=[f.result(timeout=40) for f in futures]
                winners=[v for v in creations if v["passed"]]
                assert len(winners)==1 and sum(not v["passed"] for v in creations)==args.contenders-1
                assert winners[0]["data"]["sha256"]==hashlib.sha256(fresh.read_bytes()).hexdigest()
                assert any(f"unique-create-writer-{i}\n".encode()==fresh.read_bytes() for i in range(args.contenders))
                passed("competing create-only publications produce exactly one winner without overwrite")
                # Replace is likewise version-pinned; simultaneous replacement
                # with the same old digest must not silently lose prior writes.
                before_replace=hashlib.sha256(fresh.read_bytes()).hexdigest()
                barrier=threading.Barrier(args.contenders)
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.contenders) as pool:
                    futures=[pool.submit(call_once,url,token,"text_file_write",{
                        "path":str(fresh),"mode":"replace","expected_sha256":before_replace,
                        "content":f"unique-replace-writer-{i}\n"
                    },barrier) for i in range(args.contenders)]
                    replacements=[f.result(timeout=40) for f in futures]
                winners=[v for v in replacements if v["passed"]]
                assert len(winners)==1 and sum(not v["passed"] for v in replacements)==args.contenders-1
                assert winners[0]["data"]["sha256"]==hashlib.sha256(fresh.read_bytes()).hexdigest()
                assert any(f"unique-replace-writer-{i}\n".encode()==fresh.read_bytes() for i in range(args.contenders))
                passed("competing SHA-pinned replacements produce exactly one winner without lost writes")
                assert not list(workspace.glob(".hepta-text-*"))
                value=c.call("text_file_write",{"path":str(target),"mode":"replace",
                    "expected_sha256":previous,"content":"done 中文\n"})
                assert value["sha256"]==hashlib.sha256(target.read_bytes()).hexdigest()
                passed("follow-up single replace preserves exact content and digest")
                receipt={"schema":"hepta-dc-parity-concurrent-publisher-v1","complete":True,
                    "checks":checks,"waves":args.waves,"contenders":args.contenders,
                    "parallel_mutations_attempted":(args.waves+2)*args.contenders,
                    "accepted_parallel_writes":args.waves+2,
                    "refused_stale_parallel_writes":(args.waves+2)*(args.contenders-1),
                    "tool_count":len(catalog),"only_private_test_runtime":True,
                    "chatgpt_originated":False,"native_production_changed":False}
                output=pathlib.Path(args.out)
                if output.exists():raise FileExistsError("do not overwrite prior receipt")
                output.write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n")
                print("ALL_PASS",len(checks),flush=True)
            finally:
                if controller.poll() is None:controller.terminate()
                controller.wait(timeout=15)

if __name__=="__main__":main()
