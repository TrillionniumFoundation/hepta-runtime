#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare actual HIA multi-file owners with the unchanged Rust declarations."""
from __future__ import annotations
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
from pathlib import Path

OPTIONS = None
OBSERVATIONS = {"private_calls":0,"native_calls":0,"growth_calls":0,
    "typed_comparisons":0,"original_validation_comparisons":0,"config_calls":0,
    "synthetic_plan_sequences":0}
U64 = lambda raw, at: struct.unpack_from("<Q",raw,at)[0]
PACK = lambda *values: struct.pack("<"+"Q"*len(values),*values)
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: json.dumps(value,ensure_ascii=False,separators=(",",":")).encode()

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


def cases():
    rows=[]
    def add(name,value=None,raw=None):
        rows.append({"case_id":name,"raw_json":raw if raw is not None else ENCODE(value).decode()})
    base={"host":"a","paths":["/tmp/a"]}
    add("normal",base)
    for name,value in [("empty",{}),("missing-host",{"paths":["/a"]}),("missing-paths",{"host":"a"})]:
        add(name,value)
    for field in ("host","paths","max_file_bytes","max_response_bytes"):
        values=[None,False,True,0,1,-1,1.0,1.5,"",{},[],["/tmp/a"]]
        for index,value in enumerate(values):
            add("types-"+field+"-"+str(index),dict(base,**{field:value}))
    for field in ("max_file_bytes","max_response_bytes"):
        values=[0,1,1023,1024,16384,65535,65536,65537,262144,262145,
            (1<<63)-1,1<<63,(1<<64)-1,-(1<<63),-0.0,1e100]
        for index,value in enumerate(values):
            add("numbers-"+field+"-"+str(index),dict(base,**{field:value}))
        for index,raw in enumerate(["18446744073709551616","-9223372036854775809","1e-100","1e20"]):
            add("raw-number-"+field+"-"+str(index),raw='{"host":"a","paths":["/a"],"'+field+'":'+raw+'}')
    for count in (0,1,2,16,17,65,300):
        add("strings-count-"+str(count),dict(base,paths=["/tmp/"+str(i) for i in range(count)]))
    for at in (0,1,16,64,257):
        for index,value in enumerate([None,False,3,3.5,{},[]]):
            paths=["/tmp/"+str(i) for i in range(at)]+[value]
            add("late-element-"+str(at)+"-"+str(index),dict(base,paths=paths))
    for index,value in enumerate(["","relative","/","/a/","//a","/a//b","/a/./b","/a/../b",
                                  "/a\0b","/a\nb",'/a"b',"/雪/中文.txt","/"+("a"*4095),"/"+("a"*4096)]):
        add("path-shape-"+str(index),dict(base,paths=[value]))
    for index,paths in enumerate([["/a","/a"],["/a","/a","/bad//path"],
                                  ["/a","/bad//path","/a"],["/a","/a/."],["/a","/ab"]]):
        add("path-order-"+str(index),dict(base,paths=paths))
    for file in (None,0,1,65536,65537):
        for response in (None,0,1024,262144,262145):
            add("limits-"+str(file)+"-"+str(response),
                dict(base,max_file_bytes=file,max_response_bytes=response))
    for index,key in enumerate(["root","ssh_target","sudo","command","offset",
                                "aa","zz","\x60quoted\x60","\0雪\n"]):
        add("unknown-"+str(index),dict(base,**{key:"secret"}))
    for index,host in enumerate(["","雪🙂\0\n",'"\\\b\f\r',"h"*70000]):
        add("host-text-"+str(index),dict(base,host=host))
    add("long-path-typed",dict(base,paths=["p"*70000]))
    add("many-empty-typed",dict(base,paths=[""]*1200))
    add("large-late-type",dict(base,paths=[""]*1200+[False]))
    add("unknown-long",dict(base,**{"z"*70000:None}))
    add("duplicate-host-last",raw='{"paths":["/a"],"host":false,"host":"a"}')
    add("duplicate-paths-last",raw='{"host":"a","paths":null,"paths":["/a"]}')
    add("escaped-keys",raw='{"ho\\u0073t":"a","pa\\u0074hs":["/a"]}')
    add("maxima",dict(base,max_file_bytes=(1<<64)-1,max_response_bytes=(1<<64)-1))
    return rows

def feedback(value,status=0):
    return b"HRCFGM01"+PACK(status,0,len(value))+value

def plan_wire(typed,phase=0,index=0,roots=b"",reply=b""):
    return b"HMRLQ001"+PACK(phase,index,len(typed),len(roots),len(reply))+typed+roots+reply

def config_query(operation,host,path=b""):
    return b"HRCFGQ01"+PACK(operation,40+len(host)+len(path),0,0,0,len(host),len(path))+host+path

def identity(path):
    raw=path.read_bytes()
    return {"path":str(path),"bytes":len(raw),"sha256":SHA(raw)}

class MultiOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(runtime/"scripts"))
        from hia_native_loader import NativeModule
        cls.params=NativeModule(OPTIONS.params,manifest_sha256=SHA(OPTIONS.params.read_bytes()))
        cls.plan=NativeModule(OPTIONS.plan,manifest_sha256=SHA(OPTIONS.plan.read_bytes()))
        cls.rows=cases()
        request=b"".join(ENCODE(row)+b"\n" for row in cls.rows)
        (OPTIONS.output/"original-input.jsonl").write_bytes(request)
        start=time.monotonic()
        done=subprocess.run([str(OPTIONS.reference)],input=request,capture_output=True,timeout=120)
        (OPTIONS.output/"original-output.jsonl").write_bytes(done.stdout)
        (OPTIONS.output/"original.stderr").write_bytes(done.stderr)
        if done.returncode or done.stderr:
            raise AssertionError(("original observer failed",done.returncode,done.stderr[-2000:]))
        observed=[json.loads(line) for line in done.stdout.splitlines()]
        if [row["case_id"] for row in observed]!=[row["case_id"] for row in cls.rows]:
            raise AssertionError("Original comparison identities differ")
        cls.reference={row["case_id"]:row["result"] for row in observed}
        cls.typed_frames={}
        OBSERVATIONS["original_observer_seconds"]=time.monotonic()-start

    @classmethod
    def tearDownClass(cls):
        cls.params.close()
        cls.plan.close()

    def typed(self,canonical):
        wire=b"HMRPQ001"+PACK(len(canonical),1)+canonical
        out_capacity=320
        workspace_capacity=0
        for _ in range(5):
            code,out,workspace=self.params.invoke_raw(wire,output_capacity=out_capacity,
                workspace_capacity=workspace_capacity,output_fill=165,workspace_fill=90)
            OBSERVATIONS["native_calls"]+=1
            self.assertEqual(code,256)
            self.assertEqual(out[:8],b"HMRPR001")
            status=U64(out,8)
            if status==2:
                self.assertEqual(workspace,b"Z"*workspace_capacity)
                self.assertEqual(out[256:],b"\xa5"*(out_capacity-256))
                workspace_capacity=U64(out,80)+16
                OBSERVATIONS["growth_calls"]+=1
                continue
            if status==3:
                self.assertEqual(out[256:],b"\xa5"*(out_capacity-256))
                out_capacity=U64(out,80)+31
                OBSERVATIONS["growth_calls"]+=1
                continue
            self.assertIn(status,(0,1))
            size=256+U64(out,72) if status else 256+U64(out,56)+U64(out,64)
            self.assertLessEqual(size,len(out))
            self.assertEqual(out[size:],b"\xa5"*(len(out)-size))
            return out[:size]
        self.fail("typed growth did not converge")

    def planned(self,wire):
        out_capacity=128
        workspace_capacity=512
        for _ in range(3):
            code,out,workspace=self.plan.invoke_raw(wire,output_capacity=out_capacity,
                workspace_capacity=workspace_capacity,output_fill=165,workspace_fill=90)
            OBSERVATIONS["native_calls"]+=1
            if code==0xffffffd0:
                self.assertEqual(out[:8],b"HGRWS002")
                self.assertEqual(U64(out,8),2)
                self.assertEqual(out[32:],b"\xa5"*(len(out)-32))
                out_capacity=U64(out,16)+31
                OBSERVATIONS["growth_calls"]+=1
                continue
            self.assertLess(code,0xffff0000)
            self.assertEqual(out[:8],b"HMRLR001")
            self.assertEqual(code,64+U64(out,48)+U64(out,56))
            self.assertEqual(out[code:],b"\xa5"*(len(out)-code))
            return out[:code]
        self.fail("plan growth did not converge")

    def actual_typed(self,value,fixture):
        raw=ENCODE(value)
        code,mapped,_=fixture.call(10,b"HJSMS002"+PACK(1,len(raw))+raw)
        self.assertEqual(code,32)
        self.assertEqual(mapped[:8],b"HJSVR002")
        self.assertEqual(U64(mapped,8),0)
        return self.typed(mapped[32:])

    def test_01_complete_typed_original_matrix(self):
        with Fixture(OPTIONS.output/"actual-map",OPTIONS.fixture,None) as fixture:
            for row in self.rows:
                with self.subTest(case=row["case_id"]):
                    expected=self.reference[row["case_id"]]
                    self.assertTrue(expected["value_admitted"])
                    raw=row["raw_json"].encode()
                    code,mapped,_=fixture.call(10,b"HJSMS002"+PACK(1,len(raw))+raw)
                    self.assertEqual((code,mapped[:8],U64(mapped,8)),(32,b"HJSVR002",0))
                    self.assertEqual(mapped[32:],expected["canonical"].encode())
                    result=self.typed(mapped[32:])
                    self.assertEqual(result,bytes.fromhex(expected["typed_frame_hex"]))
                    self.typed_frames[row["case_id"]]=result
                    OBSERVATIONS["typed_comparisons"]+=1
        for name,count in (("strings-count-17",17),("strings-count-300",300),("many-empty-typed",1200)):
            result=self.typed_frames[name]
            self.assertEqual((U64(result,8),U64(result,48)),(0,count))
        result=self.typed_frames["large-late-type"]
        self.assertEqual(U64(result,8),1)
        self.assertEqual(result[256:],b"invalid type: boolean \x60false\x60, expected a string")

    def test_02_original_business_validation_order(self):
        for row in self.rows:
            expected=self.reference[row["case_id"]]
            if not expected["typed_ok"]:
                continue
            with self.subTest(case=row["case_id"]):
                typed=bytes.fromhex(expected["typed_frame_hex"])
                result=self.planned(plan_wire(typed))
                wanted=expected["validation"]
                if wanted["ok"]:
                    host=expected["normalized"]["host"].encode()
                    self.assertEqual((U64(result,8),U64(result,16),U64(result,24)),(2,1,0))
                    self.assertEqual((U64(result,32),U64(result,40)),
                        (wanted["max_file_bytes"],wanted["max_response_bytes"]))
                    self.assertEqual(result[64:],config_query(11,host))
                else:
                    self.assertEqual(U64(result,8),1)
                    self.assertEqual(result[64:],wanted["error"].encode())
                self.assertEqual(U64(result,56),0)
                OBSERVATIONS["original_validation_comparisons"]+=1

    def test_03_complete_caller_continuations_and_failures(self):
        with Fixture(OPTIONS.output/"plan-map",OPTIONS.fixture,None) as fixture:
            params={"host":"a","paths":["/a/雪",'/a/quote"line\n',"/a/third"],
                "max_file_bytes":65536,"max_response_bytes":262144}
            typed=self.actual_typed(params,fixture)
            roots=[b"/a","/a/雪\n\"".encode(),b"/"]
            result=self.planned(plan_wire(typed))
            self.assertEqual(result[64:],config_query(11,b"a"))
            isolated=self.planned(plan_wire(typed,1,reply=feedback(b"HRCFMOD1"+PACK(0))))
            self.assertEqual(U64(isolated,8),1)
            self.assertEqual(isolated[64:],b"read_multiple_files requires a configured operator host")
            error=b"unknown host \x60a\x60; call host_list for configured names"
            failed=self.planned(plan_wire(typed,1,reply=feedback(error,1)))
            self.assertEqual(failed[64:],error)
            result=self.planned(plan_wire(typed,1,reply=feedback(b"HRCFMOD1"+PACK(1))))
            self.assertEqual(result[64:],config_query(12,b"a",params["paths"][0].encode()))
            retained=b""
            for index,root in enumerate(roots):
                if index:
                    expected_tail=b"".join(PACK(len(p))+p for p in roots[:index])
                    self.assertEqual(retained,expected_tail)
                for diagnostic in (b"read path denied","configured policy:\nsecret-free error".encode()):
                    failed=self.planned(plan_wire(typed,2,index,retained,feedback(diagnostic,1)))
                    self.assertEqual(U64(failed,8),1)
                    self.assertEqual(failed[64:],diagnostic)
                    self.assertEqual(U64(failed,56),0)
                result=self.planned(plan_wire(typed,2,index,retained,feedback(root)))
                payload_size=U64(result,48)
                payload=result[64:64+payload_size]
                retained=result[64+payload_size:]
                if index+1<len(roots):
                    self.assertEqual((U64(result,8),U64(result,16),U64(result,24)),(2,2,index+1))
                    self.assertEqual(payload,config_query(12,b"a",params["paths"][index+1].encode()))
                else:
                    expected={"files":[{"path":path,"root":root.decode()} for path,root in zip(params["paths"],roots)],
                        "max_file_bytes":65536,"max_response_bytes":262144}
                    self.assertEqual((U64(result,8),U64(result,16),U64(result,24)),(3,0,0))
                    self.assertEqual(payload,json.dumps(expected,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode())
                    self.assertEqual(retained,b"")
            OBSERVATIONS["synthetic_plan_sequences"]+=1
            long_typed=self.actual_typed({"host":"h"*70000,"paths":["/a","/b"]},fixture)
            long_roots=[b"/"+b"x"*70000,b"/"+b"y"*70000]
            first=self.planned(plan_wire(long_typed,2,0,reply=feedback(long_roots[0])))
            retained=first[64+U64(first,48):]
            self.assertEqual(retained,PACK(len(long_roots[0]))+long_roots[0])
            last=self.planned(plan_wire(long_typed,2,1,retained,feedback(long_roots[1])))
            self.assertEqual(U64(last,8),3)
            self.assertEqual(json.loads(last[64:])["files"][1]["root"],long_roots[1].decode())
            OBSERVATIONS["synthetic_plan_sequences"]+=1

    def test_04_growth_and_private_frame_refusals(self):
        canonical=b'{"host":"a","paths":["/a"]}'
        wire=b"HMRPQ001"+PACK(len(canonical),1)+canonical
        for capacity in (0,1,255):
            code,out,w=self.params.invoke_raw(wire,output_capacity=capacity,workspace_capacity=32,
                output_fill=165,workspace_fill=90)
            self.assertEqual((code,out,w),(0xfffffffe,b"\xa5"*capacity,b"Z"*32))
        for bad in (b"",wire[:23],b"X"+wire[1:],wire[:8]+PACK(0)+wire[16:],
                    wire[:16]+PACK(2)+wire[24:],wire[:-1]):
            code,out,w=self.params.invoke_raw(bad,output_capacity=512,workspace_capacity=70000,
                output_fill=165,workspace_fill=90)
            self.assertEqual((code,out,w),(0xffffffff,b"\xa5"*512,b"Z"*70000))
        needed=max(len(wire),512)+65536
        for capacity in (0,512,needed-1):
            code,out,w=self.params.invoke_raw(wire,output_capacity=512,workspace_capacity=capacity,
                output_fill=165,workspace_fill=90)
            self.assertEqual((code,U64(out,8),U64(out,80)),(256,2,needed))
            self.assertEqual(out[256:],b"\xa5"*256)
            self.assertEqual(w,b"Z"*capacity)
        typed=bytes.fromhex(self.reference["normal"]["typed_frame_hex"])
        valid=plan_wire(typed)
        changed=[]
        for at,value in ((0,0),(8,3),(16,1),(24,0),(32,1),(40,1),(48,0),(56,1),
                         (64,0),(72,4),(120,1),(128,1),(136,1)):
            raw=bytearray(valid);struct.pack_into("<Q",raw,at,value);changed.append(bytes(raw))
        changed += [b"",valid[:303],valid[:-1],valid+b"x",
            plan_wire(typed,1,reply=feedback(b"HRCFMOD1"+PACK(2))),
            plan_wire(typed,1,reply=feedback(b"HRCFMOD1"+PACK(1))+b"x"),
            plan_wire(typed,2,0,roots=PACK(1)+b"/",reply=feedback(b"/")),
            plan_wire(typed,2,1,roots=b"",reply=feedback(b"/")),
            plan_wire(typed,2,0,reply=feedback(b"\xff"))]
        bad_utf8=bytearray(valid);bad_utf8[304]=255;changed.append(bytes(bad_utf8))
        for index,bad in enumerate(changed):
            with self.subTest(malformed=index):
                code,out,w=self.plan.invoke_raw(bad,output_capacity=512,workspace_capacity=512,
                    output_fill=165,workspace_fill=90)
                self.assertEqual((code,out,w),(0xffffffff,b"\xa5"*512,b"Z"*512))
        for capacity in (0,1,63):
            code,out,w=self.plan.invoke_raw(valid,output_capacity=capacity,workspace_capacity=512,
                output_fill=165,workspace_fill=90)
            self.assertEqual((code,out,w),(0xfffffffe,b"\xa5"*capacity,b"Z"*512))
        code,out,w=self.plan.invoke_raw(valid,output_capacity=512,workspace_capacity=511,
            output_fill=165,workspace_fill=90)
        self.assertEqual(code,0xffffffd0)
        self.assertEqual(out[:32],b"HGRWS002"+PACK(1,512,0))
        self.assertEqual(out[32:],b"\xa5"*480)
        self.assertEqual(w,b"Z"*511)

def main():
    global OPTIONS
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("params","plan","fixture","reference","output"):
        parser.add_argument("--"+name,required=True,type=Path)
    OPTIONS=parser.parse_args()
    OPTIONS.output.mkdir(parents=True,exist_ok=False)
    inputs=[OPTIONS.params,OPTIONS.plan,OPTIONS.fixture,OPTIONS.reference,Path(__file__).resolve()]
    for path in (OPTIONS.params,OPTIONS.plan):
        record=json.loads(path.read_bytes())
        inputs.extend(path.parent/record[key] for key in ("source","image"))
    before=[identity(p) for p in inputs]
    started=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MultiOwnerTests))
    after=[identity(p) for p in inputs]
    unchanged=before==after
    passed=result.wasSuccessful() and unchanged
    report={"schema":"hepta.runtime.public-multi-owner-controls.v1","status":"PASS" if passed else "FAIL",
        "tests_run":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
        "skipped":len(result.skipped),"expected_failures":len(result.expectedFailures),
        "unexpected_successes":len(result.unexpectedSuccesses),"observations":OBSERVATIONS,
        "all_input_files_unchanged":unchanged,"inputs":before,"seconds":time.monotonic()-started,
        "python_isolated":sys.flags.isolated,"python_optimize":sys.flags.optimize,
        "synthetic_config_replies_only":True,"actual_remote_filesystem_qualified":False,
        "public_route_integrated":False,"whole_runtime_replaced":False}
    (OPTIONS.output/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:report[k] for k in ("status","tests_run","failures","errors","skipped","observations","seconds")},sort_keys=True))
    raise SystemExit(0 if passed else 1)

if __name__=="__main__":
    main()
