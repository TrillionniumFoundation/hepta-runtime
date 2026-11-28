#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compose actual installed configuration with both HIA multi-file owners."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
import time
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_public_multi_read_owners as support
from test_public_multi_read_owners import Fixture,PACK,U64,SHA,ENCODE,plan_wire,config_query,identity

OPTIONS=None
OBSERVATIONS={"sequences":0,"config_calls":0,"queries":0,"business_refusals":0,"config_refusals":0}

def make_config(root):
    root.mkdir()
    allowed=root/"allowed";allowed.mkdir()
    nested=allowed/"nested";nested.mkdir()
    other=root/"other";other.mkdir()
    document={"state_dir":str(root/"state"),"controller_workspace_roots":[str(root)],
        "hosts":{
            "a":{"ssh_target":"b","execution_mode":"operator","remote_state_dir":str(root/"remote-a"),
                 "allowed_read_path_prefixes":[str(allowed),str(nested),str(nested)+"/"]},
            "b":{"ssh_target":"target-b","execution_mode":"operator","remote_state_dir":str(root/"remote-b"),
                 "allowed_read_path_prefixes":[str(other)]},
            "isolated":{"ssh_target":"isolated-target","execution_mode":"isolated",
                 "remote_state_dir":str(root/"remote-isolated"),"allowed_read_path_prefixes":[str(allowed)]},
            "empty":{"ssh_target":"empty-target","execution_mode":"operator",
                 "remote_state_dir":str(root/"remote-empty"),"allowed_read_path_prefixes":[]}}}
    document["hosts"]["d"]=dict(document["hosts"]["b"],ssh_target="target-d",remote_state_dir=str(root/"remote-d"))
    path=root/"config.json";path.write_bytes(ENCODE(document))
    return path,document,allowed,nested,other

class MultiConfiguredTests(unittest.TestCase):
    typed=support.MultiOwnerTests.typed
    planned=support.MultiOwnerTests.planned
    actual_typed=support.MultiOwnerTests.actual_typed

    @classmethod
    def setUpClass(cls):
        runtime=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(runtime/"scripts"))
        from hia_native_loader import NativeModule
        cls.params=NativeModule(OPTIONS.params,manifest_sha256=SHA(OPTIONS.params.read_bytes()))
        cls.plan=NativeModule(OPTIONS.plan,manifest_sha256=SHA(OPTIONS.plan.read_bytes()))

    @classmethod
    def tearDownClass(cls):
        cls.params.close();cls.plan.close()

    def walk(self,fixture,value):
        typed=self.actual_typed(value,fixture)
        self.assertEqual(U64(typed,8),0)
        current=plan_wire(typed)
        requests=[]
        for _ in range(34):
            result=self.planned(current)
            status=U64(result,8);size=U64(result,48)
            payload=result[64:64+size];roots=result[64+size:]
            if status in (1,3):
                self.assertEqual(roots,b"")
                OBSERVATIONS["sequences"]+=1
                OBSERVATIONS["queries" if status==3 else
                    "config_refusals" if requests else "business_refusals"]+=1
                return status,payload,requests
            self.assertEqual(status,2)
            operation=U64(payload,8)
            self.assertEqual(operation,11 if not requests else 12)
            requests.append(payload)
            code,reply,_=fixture.call(11,payload)
            OBSERVATIONS["config_calls"]+=1
            self.assertEqual(code,len(reply))
            self.assertEqual(reply[:8],b"HRCFGM01")
            current=plan_wire(typed,U64(result,16),U64(result,24),roots,reply)
        self.fail("Configured multi-file plan did not finish within original sixteen paths")

    def test_01_actual_names_roots_order_and_immutable_install(self):
        root=OPTIONS.output/"success"
        cfg,doc,allowed,nested,other=make_config(root)
        with Fixture(root/"process",OPTIONS.fixture,cfg) as fixture:
            paths=[str(allowed/"first"),str(nested/"child"),str(nested)]
            params={"host":"a","paths":paths,"max_file_bytes":65536,"max_response_bytes":262144}
            status,payload,requests=self.walk(fixture,params)
            self.assertEqual(status,3)
            self.assertEqual(requests,[config_query(11,b"a")]+[
                config_query(12,b"a",p.encode()) for p in paths])
            expected={"files":[{"path":path,"root":root} for path,root in
                zip(paths,[str(allowed),str(nested)+"/",str(nested)])],
                "max_file_bytes":65536,"max_response_bytes":262144}
            self.assertEqual(payload,json.dumps(expected,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode())
            paths=[str(allowed/("file-"+str(i))) for i in range(16)]
            status,payload,requests=self.walk(fixture,{"host":"a","paths":paths})
            self.assertEqual(status,3)
            self.assertEqual(len(requests),17)
            self.assertEqual(json.loads(payload),{"files":[{"path":p,"root":str(allowed)} for p in paths],
                "max_file_bytes":16384,"max_response_bytes":65536})
            # Original host(name) is exact; check_remote_path separately retains
            # host_by_alias's first BTreeMap name-or-target match, which is a here.
            status,payload,requests=self.walk(fixture,{"host":"b","paths":[str(other/"file")]})
            self.assertEqual(status,1)
            self.assertEqual(payload,b"path \x60"+str(other/"file").encode()+
                b"\x60 is outside configured read roots on host \x60a\x60")
            self.assertEqual(requests,[config_query(11,b"b"),config_query(12,b"b",str(other/"file").encode())])
            status,payload,requests=self.walk(fixture,{"host":"d","paths":[str(other/"file")]})
            self.assertEqual(status,3)
            self.assertEqual(json.loads(payload)["files"][0]["root"],str(other))
            self.assertEqual(requests[0],config_query(11,b"d"))
            doc["hosts"]["a"]["execution_mode"]="isolated"
            doc["hosts"]["a"]["allowed_read_path_prefixes"]=[str(other)]
            cfg.write_bytes(ENCODE(doc))
            status,payload,requests=self.walk(fixture,{"host":"a","paths":[str(allowed/"after-change")]})
            self.assertEqual(status,3)
            self.assertEqual(json.loads(payload)["files"][0]["root"],str(allowed))

    def test_02_original_order_before_config_and_policy_failures(self):
        root=OPTIONS.output/"refusals"
        cfg,doc,allowed,nested,other=make_config(root)
        with Fixture(root/"process",OPTIONS.fixture,cfg) as fixture:
            for value,wanted in [
                ({"host":"missing","paths":[]} ,b"read_multiple_files requires 1..16 paths"),
                ({"host":"missing","paths":[str(allowed/"file")],"max_file_bytes":0},
                 b"max_file_bytes must be 1..65536; larger files require binary_read"),
                ({"host":"missing","paths":["relative"]},
                 b"batch paths must be bounded absolute paths without empty, dot or traversal components"),
                ({"host":"missing","paths":[str(allowed/"file")]*2},
                 b"read_multiple_files paths must be distinct")]:
                status,payload,requests=self.walk(fixture,value)
                self.assertEqual((status,payload,requests),(1,wanted,[]))
            for host in ("target-b","unknown","h"*70000):
                status,payload,requests=self.walk(fixture,{"host":host,"paths":[str(allowed/"file")]})
                self.assertEqual(status,1)
                self.assertEqual(payload,b"unknown host \x60"+host.encode()+b"\x60; call host_list for configured names")
                self.assertEqual(requests,[config_query(11,host.encode())])
            status,payload,requests=self.walk(fixture,{"host":"isolated","paths":[str(other/"outside")]})
            self.assertEqual(status,1)
            self.assertEqual(payload,b"read_multiple_files requires a configured operator host")
            self.assertEqual(requests,[config_query(11,b"isolated")])
            for host,path in [("empty",str(allowed/"file")),("a",str(other/"outside"))]:
                code,original,_=fixture.call(11,config_query(9,host.encode(),path.encode()))
                self.assertEqual((code,U64(original,8)),(len(original),1))
                status,payload,requests=self.walk(fixture,{"host":host,"paths":[path]})
                self.assertEqual((status,payload),(1,original[32:]))
                self.assertEqual(requests,[config_query(11,host.encode()),config_query(12,host.encode(),path.encode())])
            paths=[str(allowed/"first"),str(other/"denied"),str(allowed/"never-checked")]
            status,payload,requests=self.walk(fixture,{"host":"a","paths":paths})
            self.assertEqual(status,1)
            self.assertEqual(requests,[config_query(11,b"a")]+[
                config_query(12,b"a",path.encode()) for path in paths[:2]])
            self.assertNotIn(b'"files":',payload)

    def test_03_disabled_configuration_is_preserved(self):
        root=OPTIONS.output/"disabled";root.mkdir()
        with Fixture(root/"process",OPTIONS.fixture,None) as fixture:
            request=config_query(11,b"a")
            code,reply,_=fixture.call(11,request)
            self.assertEqual((code,U64(reply,8)),(len(reply),1))
            status,payload,requests=self.walk(fixture,{"host":"a","paths":["/tmp/a"]})
            self.assertEqual((status,payload,requests),(1,reply[32:],[request]))

def main():
    global OPTIONS
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("params","plan","fixture","output"):
        parser.add_argument("--"+name,required=True,type=Path)
    OPTIONS=parser.parse_args()
    OPTIONS.output.mkdir(parents=True,exist_ok=False)
    paths=[OPTIONS.params,OPTIONS.plan,OPTIONS.fixture,Path(__file__).resolve(),Path(support.__file__).resolve()]
    for p in (OPTIONS.params,OPTIONS.plan):
        manifest=json.loads(p.read_bytes())
        paths.extend(p.parent/manifest[k] for k in ("source","image"))
    before=[identity(p) for p in paths]
    started=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MultiConfiguredTests))
    after=[identity(p) for p in paths]
    passed=result.wasSuccessful() and before==after
    report={"schema":"hepta.runtime.public-multi-config-controls.v1","status":"PASS" if passed else "FAIL",
        "tests_run":result.testsRun,"errors":len(result.errors),"failures":len(result.failures),
        "skipped":len(result.skipped),"expected_failures":len(result.expectedFailures),
        "unexpected_successes":len(result.unexpectedSuccesses),"seconds":time.monotonic()-started,
        "observations":OBSERVATIONS,"native_owner_observations":support.OBSERVATIONS,"inputs":before,
        "all_input_files_unchanged":before==after,"python_isolated":sys.flags.isolated,
        "python_optimize":sys.flags.optimize,"actual_installed_configuration":True,
        "synthetic_configuration_replies":False,"actual_remote_filesystem_qualified":False,
        "public_route_integrated":False,"whole_runtime_replaced":False}
    (OPTIONS.output/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:report[k] for k in ("status","tests_run","errors","failures","skipped","observations","native_owner_observations","seconds")},sort_keys=True))
    raise SystemExit(0 if passed else 1)

if __name__=="__main__":
    main()
