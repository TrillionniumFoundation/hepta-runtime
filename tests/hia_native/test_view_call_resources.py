"""Run ten real mechanical controls and one fresh C compile, without HIA stubs
being counted as production semantics. Every child has a 20-second deadline.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_view_resource_qualification as reference

CAPTURE=None
INITIAL=None
COMPILER=None
EXECUTABLE=None
PROCESSES=[]
STARTED=time.monotonic()


def write_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as handle:
        handle.write(reference.encode(value)+b'\n')


def stream(name,raw):
    path=CAPTURE/name
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as handle:
        handle.write(raw)
    return dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def descriptor(name):
    raw=(CAPTURE/name).read_bytes()
    return dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def execute(name,command,environment,binary):
    started=time.monotonic()
    row=dict(name=name,command=command,cwd=str(ROOT),environment=environment,
             timeout_seconds=20,elapsed_seconds=None,exit_code=None,timed_out=False,
             start_error=None,pid=None,binary=binary)
    stdout=b'';stderr=b''
    try:
        process=subprocess.Popen(command,cwd=ROOT,env=environment,stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        row['pid']=process.pid
        try:
            stdout,stderr=process.communicate(input=b'',timeout=20)
        except subprocess.TimeoutExpired:
            row['timed_out']=True
            os.killpg(process.pid,signal.SIGKILL)
            stdout,stderr=process.communicate()
        row['exit_code']=process.returncode
    except OSError as error:
        row['start_error']=str(error)
    row['elapsed_seconds']=time.monotonic()-started
    for suffix,raw in (('stdin',b''),('stdout',stdout),('stderr',stderr)):
        row[suffix]=stream('processes/'+name+'.'+suffix,raw)
    write_json(CAPTURE/'processes'/ (name+'.json'),row)
    PROCESSES.append(row)
    return row,stdout,stderr


class ViewEngineResources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global CAPTURE,INITIAL,COMPILER,EXECUTABLE
        output=Path(os.environ['HIA_VIEW_CALL_QUALIFICATION_OUTPUT']).resolve()
        CAPTURE=Path(os.environ['HIA_VIEW_RESOURCE_CAPTURE_DIR']).resolve()
        if CAPTURE!=output/reference.FOLDER:
            raise ValueError('resource capture must be the fixed qualification folder')
        CAPTURE.mkdir(parents=True,exist_ok=False)
        INITIAL=reference.source_binding(ROOT)
        for name in reference.SOURCE_PATHS:
            stream('sources/'+name,(ROOT/name).read_bytes())
        compiler_path=Path(shutil.which('cc',path='/usr/bin:/bin') or '').resolve()
        if not compiler_path.is_file():
            raise ValueError('a real C compiler is required')
        compiler_raw=compiler_path.read_bytes()
        COMPILER=dict(executable=str(compiler_path),snapshot=stream('build/compiler.bin',compiler_raw))
        executable_path=CAPTURE/'build/view-engine-resource-control'
        if executable_path.exists():
            raise ValueError('fresh output executable already exists')
        command=[str(compiler_path),*reference.CC_FLAGS,'-o',str(executable_path),
                 str(ROOT/'tests/hia_native/view_engine_resource_control.c'),
                 str(ROOT/'tests/hia_native/view_engine_resource_stubs.S'),
                 str(ROOT/'scripts/view_call_engine.S')]
        row,stdout,stderr=execute('compile',command,reference.COMPILE_ENV,COMPILER['snapshot'])
        if row['exit_code']!=0 or row['timed_out'] or row['start_error']:
            raise AssertionError('actual fresh C compilation failed: '+stderr.decode(errors='replace'))
        if stdout:
            raise AssertionError('compiler unexpectedly emitted stdout')
        EXECUTABLE=descriptor('build/view-engine-resource-control')
        if reference.source_binding(ROOT)!=INITIAL:
            raise AssertionError('source changed while compiling')

    def control(self,index):
        name,args=reference.CONTROL_SPECS[index]
        self.assertEqual(descriptor(EXECUTABLE['path']),EXECUTABLE)
        command=[str(CAPTURE/EXECUTABLE['path']),*args]
        row,stdout,stderr=execute(name,command,reference.CONTROL_ENV,EXECUTABLE)
        self.assertIsNone(row['start_error'])
        self.assertFalse(row['timed_out'])
        self.assertEqual(row['exit_code'],0,stderr.decode(errors='replace'))
        self.assertEqual(stderr,b'')
        self.assertTrue(stdout.endswith(b'\n'))
        self.assertEqual(stdout.count(b'\n'),1)
        reference.check_control(reference.decode(stdout),args)
        self.assertEqual(descriptor(EXECUTABLE['path']),EXECUTABLE)
        self.assertEqual(reference.source_binding(ROOT),INITIAL)

    def test_00_create_destroy(self): self.control(0)
    def test_01_enomem_zero(self): self.control(1)
    def test_02_enomem_16384(self): self.control(2)
    def test_03_enomem_262144(self): self.control(3)
    def test_04_enomem_20_mib(self): self.control(4)
    def test_05_enomem_64_mib(self): self.control(5)
    def test_06_enomem_128_mib(self): self.control(6)
    def test_07_resize_preserve_and_zero(self): self.control(7)
    def test_08_resize_enomem_preserves_old(self): self.control(8)
    def test_09_unaligned_old_releases_new(self): self.control(9)


def main():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ViewEngineResources))
    unchanged=INITIAL is not None and reference.source_binding(ROOT)==INITIAL
    counts=dict(actual_controls=sum(row['name']!='compile' and row['pid'] is not None for row in PROCESSES),
                actual_c_compiles=sum(row['name']=='compile' and row['pid'] is not None for row in PROCESSES),
                actual_child_processes=sum(row['pid'] is not None for row in PROCESSES),
                actual_hia_semantic_calls=0,actual_rust_reference_processes=0)
    success=result.wasSuccessful() and result.testsRun==10 and unchanged and counts==reference.COUNTS
    report=dict(schema='hepta.runtime.view-engine-resource-tests.v1',status='PASS' if success else 'FAIL',
                groups=result.testsRun,counts=counts,elapsed_seconds=time.monotonic()-STARTED,
                source_binding=INITIAL,sources_unchanged=unchanged,
                execution=dict(runtime_root=str(ROOT),capture_root=str(CAPTURE)),
                compiler=COMPILER,executable=EXECUTABLE,processes=PROCESSES,
                hia_semantics_executed=False,rust_reference_executed=False,
                production_scope_retirement_executed=False,whole_view_replaced=False,
                c_fixture_uses_libc=True,initialization_stub_return=32,
                create_destroy_retired_bit_is_fixture=True)
    if CAPTURE is not None:
        write_json(CAPTURE/'result.json',report)
    sys.stdout.buffer.write(reference.encode(report)+b'\n')
    return 0 if success else 1


if __name__=='__main__':
    raise SystemExit(main())
