#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual installed mode/multi-root reads, including retained binary permissions."""
from pathlib import Path
import argparse,hashlib,json,struct,sys,unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tests/hia_native"))
import test_public_read_owners as carrier
Q=lambda op,name,path=b"",write=0:b"HRCFGQ01"+struct.pack("<7Q",op,40+len(name)+len(path),0,0,write,len(name),len(path))+name+path
R=lambda status,text:b"HRCFGM01"+struct.pack("<3Q",status,0,len(text))+text
OPT=None
COUNTS={"calls":0}
def call(f,q,session=0):
 code,body,header=f.call(11,q,session)
 COUNTS["calls"]+=1
 return code,body,header
def configured(folder,mode="operator",roots=None,protected=None):
 folder.mkdir()
 host={"ssh_target":"target-b","remote_state_dir":str(folder/"remote"),
       "execution_mode":mode,"allowed_read_path_prefixes":roots if roots is not None else ["/data"],
       "protected_path_prefixes":protected or []}
 value={"state_dir":str(folder/"state"),"controller_workspace_roots":[str(folder)],"hosts":{"a":host}}
 path=folder/"config.json";path.write_text(json.dumps(value))
 return path
class InstalledReadPolicy(unittest.TestCase):
 def test_exact_name_and_installed_mode(self):
  for mode,word in (("isolated",0),("operator",1)):
   folder=OPT.output/mode
   cfg=configured(folder,mode)
   with carrier.Fixture(folder/"process",OPT.fixture,cfg) as f:
    for session in (0,1):
     code,body,_=call(f,Q(11,b"a"),session)
     self.assertEqual((code,body),(48,R(0,b"HRCFMOD1"+struct.pack("<Q",word))))
    for name in (b"",b"target-b",b"x"*9000,"snow-雪\0".encode()):
     wanted=R(1,b"unknown host `"+name+b"`; call host_list for configured names")
     code,body,_=call(f,Q(11,name));self.assertEqual((code,body),(len(wanted),wanted))
    changed=json.loads(cfg.read_bytes());changed["hosts"]["a"]["execution_mode"]="isolated" if word else "operator"
    cfg.write_text(json.dumps(changed))
    self.assertEqual(call(f,Q(11,b"a"),1)[1],R(0,b"HRCFMOD1"+struct.pack("<Q",word)))
  folder=OPT.output/"absent";folder.mkdir()
  with carrier.Fixture(folder/"process",OPT.fixture,None) as f:
   for op in (10,11,12):
    self.assertEqual(call(f,Q(op,b"a",b"/data/x" if op==12 else b""))[1],
      R(1,b"runtime tools are disabled; start with --runtime-config <file>"))
 def test_original_root_and_permission_order(self):
  for mode in ("operator","isolated"):
   folder=OPT.output/("roots-"+mode)
   cfg=configured(folder,mode,["/data","/data/deep/","/data/deep/nested","/é"],["/data/protected"] if mode=="isolated" else [])
   with carrier.Fixture(folder/"process",OPT.fixture,cfg) as f:
    for path in (b"/data",b"/data/file",b"/data/deep/file",b"/data/deep/nested/file",
       b"/database",b"/else",b"/data/protected/file",b"/data/../x",b"relative",b"/data//x",
       b"/data/./x",b"/data/a\0b","/é/文".encode()):
     old=call(f,Q(9,b"a",path))[1];new=call(f,Q(12,b"a",path))[1]
     if mode=="isolated":
      self.assertEqual(new,R(1,b"read_multiple_files requires a configured operator host"))
     else:self.assertEqual(new,old)
    name=b"target-b"
    self.assertEqual(call(f,Q(12,name,b"/data/../bad"))[1],
      R(1,b"unknown host `"+name+b"`; call host_list for configured names"))
  folder=OPT.output/"long-root"
  wide="/"+("r"*12000)
  cfg=configured(folder,"operator",[wide])
  with carrier.Fixture(folder/"process",OPT.fixture,cfg) as f:
   code,body,header=call(f,Q(12,b"a",(wide+"/f").encode()))
   self.assertEqual((code,body),(32+len(wide),R(0,wide.encode())))
   self.assertGreater(carrier.U64(header,96),4096)
  folder=OPT.output/"empty-root"
  cfg=configured(folder,"operator",[])
  with carrier.Fixture(folder/"process",OPT.fixture,cfg) as f:
   original=call(f,Q(9,b"a",b"/anything"))[1]
   self.assertEqual(call(f,Q(12,b"a",b"/anything"))[1],original)
   self.assertEqual(original[:24],R(1,b"")[:24])
   self.assertIn(b"/anything",original[32:])
 def test_internal_frame_admission(self):
  folder=OPT.output/"frames";cfg=configured(folder)
  with carrier.Fixture(folder/"process",OPT.fixture,cfg) as f:
   cases=[]
   for op in (11,12):
    base=Q(op,b"a",b"/data/x" if op==12 else b"")
    cases.extend([base[:-1],base+b"x",Q(op,b"\xff",b"/data/x" if op==12 else b"")])
    for at in (24,32,40):
     b=bytearray(base);struct.pack_into("<Q",b,at,1);cases.append(bytes(b))
   cases += [Q(11,b"a",b"x"),Q(12,b"a",b"\xff")]
   for wire in cases:
    code,body,_=call(f,wire)
    self.assertEqual((code,body),(0xffffffff,b""))
def main():
 global OPT
 p=argparse.ArgumentParser()
 p.add_argument("--fixture",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
 OPT=p.parse_args();OPT.output.mkdir()
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(InstalledReadPolicy))
 report=dict(tests_run=result.testsRun,expected_tests=3,failures=len(result.failures),errors=len(result.errors),
  skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
  isolated=sys.flags.isolated,optimize=sys.flags.optimize,calls=COUNTS["calls"],fixture=str(OPT.fixture),
  fixture_sha256=hashlib.sha256(OPT.fixture.read_bytes()).hexdigest(),public_routes_qualified=False)
 ok=result.testsRun==3 and all(report[k]==0 for k in ("failures","errors","skipped","expected_failures","unexpected_successes")) and report["isolated"]==1 and report["optimize"]==0
 report["status"]="PASS" if ok else "FAIL"
 (OPT.output/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps(report,sort_keys=True))
 if not ok:raise SystemExit(1)
if __name__=="__main__":main()
