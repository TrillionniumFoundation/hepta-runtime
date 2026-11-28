#!/usr/bin/env python3
"""Complete DATA read under the unchanged original eleven-capability guard."""
import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import read_capture as reader


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',type=Path,required=True);p.add_argument('--images',type=Path,required=True)
    p.add_argument('--source-sha256',required=True);p.add_argument('--capture-sha256',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert not a.output.exists()
    expected={'common.py':'7d6f584b8cd52b0b6f0755d2c7b956d515a6a7d912b48c2d8e6c7e7f47db0be1','readonly.py':'e7ded2104b5089abe17e6f7095b60a69e84fb41ab6735b2d3d1c72547e5eb5e3'}
    for name,sha in expected.items():assert hashlib.sha256((ROOT/'guard'/name).read_bytes()).hexdigest()==sha
    original_common=load('frozen_original_guard_common',ROOT/'guard/common.py')
    previous=sys.modules['common'];sys.modules['common']=original_common
    try:guard=load('frozen_original_readonly',ROOT/'guard/readonly.py')
    finally:sys.modules['common']=previous
    began=time.monotonic()
    report=guard.guarded(lambda:reader.read_all(a.capture.resolve(),a.images.resolve(),a.source_sha256,a.capture_sha256),roots=[ROOT,a.images,a.capture])
    elapsed=time.monotonic()-began
    assert elapsed<180 and report['evidence']['status']=='COMPLETE_NATIVE_ADAPTER_DATA_PASS'
    report.update(elapsed_seconds=elapsed,timeout_seconds=180,compiler_executed=False)
    a.output.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(status=report['status'],entries=report['entries'],probes=len(report['probes']),elapsed_seconds=elapsed,evidence={k:v for k,v in report['evidence'].items()if k!='processes'}),sort_keys=True))


if __name__=='__main__':main()
