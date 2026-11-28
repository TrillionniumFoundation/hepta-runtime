#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual installed config/read owners and retain public predecessors."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import select
import struct
import subprocess
import sys
import time
import unittest

OPTIONS = None
OBSERVATIONS = {"private_calls": 0, "public_responses": 0, "catalogs": []}
U64 = lambda raw, at: struct.unpack_from("<Q", raw, at)[0]
ENCODE = lambda value: json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()

class Fixture:
    def __init__(self, folder, executable, config):
        self.folder = folder
        folder.mkdir()
        self.stderr = (folder / "stderr.bin").open("xb")
        argv = [str(executable)]
        if config is not None:
            argv += ["--runtime-config", str(config)]
        self.process = subprocess.Popen(argv, cwd=folder,
            env={"PATH": "/usr/bin:/bin", "HOME": str(folder)},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr)
        self.ordinal = 0

    def receive(self, count, deadline):
        value = bytearray()
        while len(value) < count:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.process.stdout], [], [], left)[0]:
                raise AssertionError("original 60-second exchange budget expired")
            data = os.read(self.process.stdout.fileno(), count-len(value))
            if not data:
                raise AssertionError("early native exit: " + str(self.process.poll()))
            value += data
        return bytes(value)

    def call(self, slot, payload, session=0):
        self.ordinal += 1
        request = b"HFSFXQ02" + struct.pack("<3Q", session, slot, len(payload)) + payload
        (self.folder / (str(self.ordinal)+".request.bin")).write_bytes(request)
        self.process.stdin.write(request)
        self.process.stdin.flush()
        deadline = time.monotonic() + 60
        header = self.receive(104, deadline)
        if header[:8] != b"HFSFXR02" or U64(header, 8) != session or U64(header, 16) != slot:
            raise AssertionError("actual fixture response identity differs")
        body = self.receive(U64(header, 32), deadline)
        (self.folder / (str(self.ordinal)+".response.bin")).write_bytes(header+body)
        OBSERVATIONS["private_calls"] += 1
        return U64(header, 24), body, header

    def close(self, failed=False):
        try:
            if failed:
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=30)
            else:
                self.process.stdin.close()
                status = self.process.wait(timeout=30)
                tail = self.process.stdout.read()
                if status != 0 or tail:
                    raise AssertionError(("fixture termination", status, tail.hex()))
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.stderr):
                if not stream.closed:
                    stream.close()

    def __enter__(self):
        return self

    def __exit__(self, kind, *_):
        self.close(kind is not None)

def config_file(folder, mode="operator", permissive=False):
    folder.mkdir()
    config = {
        "state_dir": str(folder/"state"),
        "controller_workspace_roots": [str(folder)],
        "hosts": {
            "a": {"ssh_target": "b", "remote_state_dir": str(folder/"remote-a"),
                  "execution_mode": mode, "allowed_read_path_prefixes": [str(folder)]},
            "b": {"ssh_target": "target-b", "remote_state_dir": str(folder/"remote-b"),
                  "execution_mode": mode, "allowed_read_path_prefixes": [str(folder)]},
        },
    }
    if permissive:
        for host in config["hosts"].values():
            host.update(allow_execute=True, allow_pty=True, allow_write=True,
                        allow_job_network=True, allowed_write_path_prefixes=[str(folder)])
    path = folder/"config.json"
    path.write_bytes(ENCODE(config))
    return path

def target_query(name):
    return b"HRCFGQ01" + struct.pack("<7Q", 10, 40+len(name), 0, 0, 0, len(name), 0) + name

def typed(fixture, kind, value):
    raw = ENCODE(value)
    code, mapped, _ = fixture.call(10, b"HJSMS002"+struct.pack("<2Q", 1, len(raw))+raw)
    if code != 32 or mapped[:8] != b"HJSVR002" or U64(mapped, 8) != 0:
        raise AssertionError("actual canonical Map owner failed")
    payload = mapped[32:]
    return fixture.call(70+kind, b"HBPRQ001"+struct.pack("<2Q", len(payload), kind)+payload)

class CurrentReadOwnerTests(unittest.TestCase):
    def test_installed_named_target_and_retained_owner(self):
        root = OPTIONS.output/"named-target"
        cfg = config_file(root)
        with Fixture(root/"process", OPTIONS.fixture, cfg) as f:
            for session in (0, 1):
                for name, wanted in ((b"a", b"b"), (b"b", b"target-b")):
                    code, body, _ = f.call(11, target_query(name), session)
                    self.assertEqual(code, 32+len(wanted))
                    self.assertEqual(body, b"HRCFGM01"+struct.pack("<3Q",0,0,len(wanted))+wanted)
            for name in (b"", b"target-b", b"x"*9000, "snow-雪\0".encode()):
                wanted = b"unknown host `"+name+b"`; call host_list for configured names"
                code, body, _ = f.call(11, target_query(name))
                self.assertEqual(body, b"HRCFGM01"+struct.pack("<3Q",1,0,len(wanted))+wanted)
                self.assertEqual(code, len(body))
            for malformed in (
                target_query(b"a")[:-1],
                target_query(b"\xff"),
                target_query(b"a")[:24]+struct.pack("<Q",1)+target_query(b"a")[32:],
            ):
                code, body, _ = f.call(11, malformed)
                self.assertEqual((code, body), (0xffffffff, b""))
            value = json.loads(cfg.read_bytes())
            value["hosts"]["b"]["ssh_target"] = "changed-on-disk"
            cfg.write_bytes(ENCODE(value))
            code, body, _ = f.call(11, target_query(b"b"), 1)
            self.assertEqual(body[32:], b"target-b")
            path = str(root/"read-file").encode()
            query = b"HRCFGQ01"+struct.pack("<7Q",9,40+1+len(path),0,0,0,1,len(path))+b"a"+path
            code, body, _ = f.call(11, query)
            self.assertEqual(body, b"HRCFGM01"+struct.pack("<3Q",0,0,len(str(root).encode()))+str(root).encode())
            self.assertEqual(code, len(body))

    def test_actual_map_typed_growth_and_original_call_plan(self):
        root = OPTIONS.output/"typed-owners"
        cfg = config_file(root)
        with Fixture(root/"process", OPTIONS.fixture, cfg) as f:
            path = str(root/"read-file")
            for kind in (1, 2):
                params = {"host": "a", "path": path}
                if kind == 2:
                    params.update(offset=(1<<64)-1, limit=0, expected_version="")
                code, body, _ = typed(f, kind, params)
                self.assertEqual(code, 256)
                self.assertEqual(body[:8], b"HBPRR001")
                self.assertEqual(U64(body,8), 0)
                self.assertEqual(U64(body,16), kind)
                self.assertEqual(body[256:257+len(path.encode())], b"a"+path.encode())
                self.assertEqual(U64(body,88),1)
                self.assertEqual(U64(body,96),len(path.encode()))
                if kind == 2:
                    self.assertEqual(U64(body,48),(1<<64)-1)
                    self.assertEqual(U64(body,56),0)
                    self.assertNotEqual(U64(body,32),0)
                typed_frame = body
                request = b"HBPLQ001"+struct.pack("<5Q",0,0,len(body),0,0)+body
                code, planned, _ = f.call(70, request)
                self.assertEqual(planned[:8], b"HBPLR001")
                self.assertEqual(U64(planned,8),2)
                self.assertEqual(U64(planned,16),kind)
                self.assertEqual(U64(planned,24),2)
                self.assertEqual(code,len(planned))
                rc, feedback, _ = f.call(11,planned[64:])
                self.assertEqual(rc,len(feedback))
                self.assertEqual(U64(feedback,8),0)
                request=b"HBPLQ001"+struct.pack("<5Q",2,0,len(typed_frame),len(feedback),0)+typed_frame+feedback
                rc, final, _ = f.call(70,request)
                self.assertEqual(rc,len(final))
                self.assertEqual(U64(final,8),3)
                expected={"op":"info" if kind==1 else "read","path":path,"root":str(root)}
                if kind==2:
                    expected.update(offset=(1<<64)-1,limit=1,expected_version="")
                self.assertEqual(json.loads(final[64:]),expected)
            for kind in (1,2):
                code, body, _ = typed(f,kind,{"host":"a"})
                self.assertEqual(code,256)
                self.assertEqual(U64(body,8),1)
                self.assertIn(b"missing field `path`",body[256:])
                params={"host":"h"*70000,"path":"p"*70000}
                code, body, header=typed(f,kind,params)
                self.assertEqual((code,U64(body,8)),(256,0))
                self.assertEqual(body[256:],b"h"*70000+b"p"*70000)
                self.assertGreater(U64(header,88),4096)
                self.assertGreater(U64(header,96),4096)

    def public(self, root, executable, config):
        root.mkdir()
        err=(root/"stderr.bin").open("xb")
        argv=[str(executable)]
        if config is not None:
            argv+=["--runtime-config",str(config)]
        p=subprocess.Popen(argv,cwd=root,env={"PATH":"/usr/bin:/bin","HOME":str(root)},
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err)
        responses=[];buffer=b""
        try:
            messages=[
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",
                 "capabilities":{},"clientInfo":{"name":"read-owner-predecessor","version":"1"}}},
                {"jsonrpc":"2.0","method":"notifications/initialized"},
                {"jsonrpc":"2.0","id":2,"method":"tools/list"},
                {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"batch_edit","arguments":{}}},
                {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"weight_bellman_plan","arguments":{}}},
            ]
            for value in messages:
                p.stdin.write(ENCODE(value)+b"\n");p.stdin.flush()
                if "id" not in value:continue
                deadline=time.monotonic()+60
                while b"\n" not in buffer:
                    left=deadline-time.monotonic()
                    self.assertGreater(left,0)
                    self.assertTrue(select.select([p.stdout],[],[],left)[0],"public deadline")
                    data=os.read(p.stdout.fileno(),65536)
                    self.assertTrue(data,"public EOF")
                    buffer+=data
                line,buffer=buffer.split(b"\n",1)
                responses.append(json.loads(line));OBSERVATIONS["public_responses"]+=1
            p.stdin.close();self.assertEqual(p.wait(timeout=30),0)
            self.assertEqual(buffer+p.stdout.read(),b"")
        finally:
            if p.poll() is None:p.kill();p.wait(timeout=30)
            for stream in (p.stdin,p.stdout,err):
                if not stream.closed:stream.close()
            (root/"responses.json").write_bytes(ENCODE(responses)+b"\n")
        return responses

    def test_current_public_catalog_and_predecessor_routes(self):
        for label,mode,permissive in (("absent",None,False),("operator","operator",False),
                                     ("operator-all","operator",True),("isolated","isolated",False)):
            root=OPTIONS.output/("public-"+label);root.mkdir()
            cfg=config_file(root/"configured",mode,permissive) if mode else None
            old=self.public(root/"baseline",OPTIONS.baseline,cfg)
            new=self.public(root/"current",OPTIONS.public,cfg)
            self.assertEqual(new,old)
            names=[v["name"] for v in new[1].get("result",{}).get("tools",[])]
            OBSERVATIONS["catalogs"].append({"configuration":label,"names":names,
                "batch_reply":new[2],"bellman_reply":new[3]})

def main():
    global OPTIONS
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("fixture","public","baseline","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    OPTIONS=parser.parse_args()
    OPTIONS.output.mkdir(parents=True,exist_ok=False)
    started=time.monotonic()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(CurrentReadOwnerTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={"schema":"hepta.runtime.public-read-owner-tests.v1",
        "status":"PASS" if result.wasSuccessful() else "FAIL",
        "tests_run":result.testsRun,"errors":len(result.errors),"failures":len(result.failures),
        "skipped":len(result.skipped),"expected_failures":len(result.expectedFailures),
        "unexpected_successes":len(result.unexpectedSuccesses),
        "python_isolated":sys.flags.isolated,"python_optimize":sys.flags.optimize,
        "elapsed_seconds":time.monotonic()-started,"observations":OBSERVATIONS,
        "public_read_routes_qualified":False}
    (OPTIONS.output/"result.json").write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)

if __name__=="__main__":
    main()
