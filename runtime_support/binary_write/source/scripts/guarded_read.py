#!/usr/bin/env python3
"""Complete composition DATA read under the retained eleven-capability guard."""
import argparse,hashlib,importlib.util,json,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import read_parent_capture,read_retry_capture,read_boundary
from evidence_common import require,encoded

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in('capture','images','build','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--capture-sha256',required=True);p.add_argument('--mode',choices=('composition','boundary'),required=True)
 a=p.parse_args();require(not a.output.exists(),'fresh complete guarded DATA receipt')
 for name,sha in {'common.py':'7d6f584b8cd52b0b6f0755d2c7b956d515a6a7d912b48c2d8e6c7e7f47db0be1','readonly.py':'e7ded2104b5089abe17e6f7095b60a69e84fb41ab6735b2d3d1c72547e5eb5e3'}.items():
  require(hashlib.sha256((ROOT/'adapter/guard'/name).read_bytes()).hexdigest()==sha,'complete retained eleven-capability guard')
 previous=sys.modules['common'];sys.modules['common']=load('composition_original_guard_common',ROOT/'adapter/guard/common.py')
 try:guard=load('composition_original_guard',ROOT/'adapter/guard/readonly.py')
 finally:sys.modules['common']=previous
 began=time.monotonic();reader=read_parent_capture if a.mode=='composition'else read_boundary
 roots=[ROOT,a.images,a.build,a.capture.parent if a.mode=='composition'else a.capture]
 report=guard.guarded(lambda:reader.read_all(a.capture,a.images,a.build,a.capture_sha256),roots=roots)
 elapsed=time.monotonic()-began;require(elapsed<600,'complete original 600-second DATA budget')
 expected='PASS_COMPLETE_FROZEN_COMPOSITION_DOMAIN'if a.mode=='composition'else'PASS_ACTUAL_COMPOSITION_BOUNDARIES'
 require(report['evidence']['status']==expected,'complete actual DATA qualification')
 report.update(elapsed_seconds=elapsed,timeout_seconds=600,compiler_executed=False,mode=a.mode)
 a.output.write_bytes(encoded(report))
 print(json.dumps(dict(status=report['status'],evidence=expected,entries=report['entries'],probes=len(report['probes']),elapsed_seconds=elapsed),sort_keys=True))

if __name__=='__main__':main()
