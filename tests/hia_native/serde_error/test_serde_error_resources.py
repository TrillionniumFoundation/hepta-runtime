# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Combined 8 MiB RawValue arena/stack boundaries, separate from base corpus."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import time
import unittest

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'native/serde_error.hepta').is_file())
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
TOKEN='$serde_json::private::RawValue'
OPTIONS=MODULE=BASE=CORPUS=None
CALLS=0
CONTROLS=[]
ELF=[]
OBSERVATIONS=[]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


def combined(depth,arrays):
    def wrap(initial):
        sizes=[]
        for _ in range(depth):
            sizes.append(len(initial))
            initial='['*arrays+json.dumps({TOKEN:initial},separators=(',',':'))+']'*arrays
        return initial,sizes
    skeleton,_=wrap('[1,]')
    spaces=8388608-len(skeleton)
    assert spaces>0
    raw,sizes=wrap(' '*spaces+'[1,]')
    assert len(raw)==8388608
    peak=1048576+len(raw)+sum(sizes)
    stack=2+depth*(arrays+2)
    message=f'trailing comma at line 1 column {spaces+4}'.encode()
    expected=b'HSJERR01'+struct.pack('<7Q',1,3,1,spaces+4,len(message),0,0)+message
    return raw.encode(),peak,stack,expected


def check_case(index,arrays):
    global CALLS
    raw,peak,stack,expected=combined(18,arrays)
    assert 67108864<peak<MODULE.metadata['workspace_capacity']
    assert 2<stack<4096
    wire=BASE.frame(raw)
    started=time.monotonic()
    with MODULE.session(output_capacity=1024,workspace_capacity=peak) as session:
        actual=session.invoke(wire);CALLS+=1
        assert actual==expected,(index,actual,expected)
        pointer=ctypes.addressof(session._workspace)
        allocation=struct.unpack('<Q',ctypes.string_at(pointer+16384+80,8))[0]
        count=struct.unpack('<Q',ctypes.string_at(pointer+16384+40,8))[0]
        assert allocation==peak and count==stack,(allocation,peak,count,stack)
    CORPUS.add('combined-raw-arena' if arrays==0 else 'combined-raw-stack',wire,actual)
    OBSERVATIONS.append(dict(ordinal=index,raw_bytes=len(raw),raw_sha256=SHA(raw),
        nesting=18,local_array_depth=arrays,workspace_exact=peak,actual_allocation=allocation,
        stack_records=count,output=actual.hex(),elapsed_seconds=time.monotonic()-started))
    # The native capacity refusal must occur before any public output write.
    code,out,_=MODULE.invoke_raw(wire,output_capacity=1024,workspace_capacity=peak-1,
        output_fill=0xA5,workspace_fill=0x5A);CALLS+=1
    assert code==0xFFFFFFFE and out==b'\xA5'*1024
    CONTROLS.append(dict(ordinal=index,workspace_capacity=peak-1,code=code,output_unchanged=True))
    if index==1:
        item=MODULE.metadata['standalone']
        binary=OPTIONS.manifest.parent/item['path']
        assert SHA(binary.read_bytes())==item['sha256']
        start=time.monotonic()
        process=subprocess.run([str(binary.resolve())],input=wire,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env={'PATH':'','LC_ALL':'C'},timeout=20)
        assert process.returncode==0 and process.stdout==expected and process.stderr==b''
        (OPTIONS.output/'elf.stdout').write_bytes(process.stdout)
        (OPTIONS.output/'elf.stderr').write_bytes(process.stderr)
        ELF.append(dict(executable_sha256=item['sha256'],exit_code=process.returncode,process_reaped=True,
            timed_out=False,timeout_seconds=20,empty_path=True,input_sha256=SHA(wire),
            stdout=BASE.pin(OPTIONS.output/'elf.stdout'),stderr=BASE.pin(OPTIONS.output/'elf.stderr'),
            elapsed_seconds=time.monotonic()-start))


class Resources(unittest.TestCase):
    def test_01_arena(self):
        check_case(0,0)

    def test_02_stack_and_elf(self):
        check_case(1,125)


def main():
    global OPTIONS,MODULE,BASE,CORPUS
    parser=argparse.ArgumentParser()
    parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_SERDE_ERROR_MANIFEST'))
    parser.add_argument('--runtime',type=Path,default=ROOT)
    parser.add_argument('--output',type=Path,required=True)
    OPTIONS=parser.parse_args();assert OPTIONS.manifest is not None
    OPTIONS.manifest=OPTIONS.manifest.resolve(strict=True)
    OPTIONS.output=OPTIONS.output.resolve();OPTIONS.output.mkdir()
    BASE=load('serde_resource_base',Path(__file__).with_name('test_serde_error.py'))
    loader=load('serde_resource_loader',OPTIONS.runtime/'scripts/hia_native_loader.py')
    MODULE=loader.NativeModule(OPTIONS.manifest,manifest_sha256=SHA(OPTIONS.manifest.read_bytes()))
    assert MODULE.metadata['source_sha256']==SHA((ROOT/'native/serde_error.hepta').read_bytes())
    source_files={str(p.relative_to(ROOT)):BASE.pin(p) for p in (ROOT/'native/serde_error.hepta',
        Path(__file__).resolve(),Path(__file__).with_name('test_serde_error.py').resolve())}
    loader_pin=BASE.pin(OPTIONS.runtime/'scripts/hia_native_loader.py')
    CORPUS=BASE.Corpus(OPTIONS.output/'corpus')
    start=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Resources))
    corpus=CORPUS.close()
    summary=dict(tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses))
    unchanged=all(BASE.pin(ROOT/name)==expected for name,expected in source_files.items()) and BASE.pin(OPTIONS.runtime/'scripts/hia_native_loader.py')==loader_pin
    passed=summary==dict(tests_run=2,failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0)
    passed=passed and unchanged and CALLS==4 and len(CONTROLS)==2 and corpus['cases']==2 and len(ELF)==1
    report=dict(schema='hepta.runtime.serde-error-resources.v1',status='PASS' if passed else 'FAIL',
        summary=summary,native_calls=CALLS,semantic_cases=corpus['cases'],controls=CONTROLS,
        actual_elf_processes=len(ELF),elf=ELF,observations=OBSERVATIONS,source_files=source_files,
        source_unchanged=unchanged,loader=loader_pin,manifest=BASE.pin(OPTIONS.manifest),module=MODULE.metadata,
        corpus=corpus,elapsed_seconds=time.monotonic()-start,original_executions=0,
        original_replay_required=True,whole_runtime_closed=False)
    (OPTIONS.output/'native-report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(status=report['status'],summary=summary,native_calls=CALLS,
        semantic_cases=corpus['cases'],controls=len(CONTROLS),actual_elf_processes=len(ELF),
        elapsed_seconds=report['elapsed_seconds']),sort_keys=True))
    MODULE.close();raise SystemExit(0 if passed else 1)


if __name__=='__main__':main()
