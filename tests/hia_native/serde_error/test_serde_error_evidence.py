# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Refuse damaged real receipts and complete-corpus substitutions."""
from pathlib import Path
import argparse
import copy
import gzip
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'native/serde_error.hepta').is_file())
OPTIONS = EVIDENCE = BASELINE = None
ACCEPTED = REFUSED = 0


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')


class EvidenceControls(unittest.TestCase):
    def test_01_complete_actual_receipts(self):
        global ACCEPTED
        actual = EVIDENCE.native_evidence(ROOT, OPTIONS.hepta, OPTIONS.manifest, OPTIONS.native_output)
        self.assertEqual(actual, BASELINE)
        ACCEPTED += 1

    def reject(self, function):
        global REFUSED
        with self.assertRaises((ValueError, KeyError, OSError, EOFError)):
            function()
        REFUSED += 1

    def test_02_compile_and_pack(self):
        build = OPTIONS.manifest.parent.parent.parent
        with tempfile.TemporaryDirectory(dir=OPTIONS.output) as temporary:
            mirror = Path(temporary)/'build'
            for name in BASELINE['build']['build_artifacts']:
                target = mirror/name;target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(build/name, target)
            manifest = mirror/OPTIONS.manifest.relative_to(build)
            folder = manifest.parent
            valid = lambda:EVIDENCE.build_evidence(ROOT, OPTIONS.hepta, manifest)
            valid()
            def mutation(path, change, extra=None):
                raw = path.read_bytes()
                if extra:
                    extra_path, extra_change = extra; previous = extra_path.read_bytes()
                try:
                    path.write_bytes(change(raw))
                    if extra:extra_path.write_bytes(extra_change(previous))
                    self.reject(valid)
                finally:
                    path.write_bytes(raw)
                    if extra:extra_path.write_bytes(previous)
            mutation(folder/'module.stdout.log', lambda _:b'{}\n')
            mutation(folder/'pack.stdout.log', lambda _:b'{"status":"returned"}\n')
            def remove_commit(raw):
                row=json.loads(raw);del row['compiler_commit'];return json.dumps(row).encode()
            mutation(manifest, remove_commit)
            def image_manifest(raw):
                row=json.loads(raw);row['image_sha256']=EVIDENCE.pin(folder/'module.image.bin')['sha256']
                return json.dumps(row).encode()
            mutation(folder/'module.image.bin', lambda raw:bytes([raw[0]^1])+raw[1:],
                     (manifest,image_manifest))
            executable=folder/EVIDENCE.object_at(manifest)['standalone']['path']
            def elf_manifest(raw):
                row=json.loads(raw);row['standalone']['sha256']=EVIDENCE.pin(executable)['sha256']
                row['standalone']['inspection']['sha256']=row['standalone']['sha256']
                return json.dumps(row).encode()
            mutation(executable, lambda raw:raw[:200]+bytes([raw[200]^1])+raw[201:],
                     (manifest,elf_manifest))
            mutation(folder/'pack.input.bin', lambda raw:raw[:8]+bytes(8)+raw[16:])

    def test_03_completed_process(self):
        with tempfile.TemporaryDirectory(dir=OPTIONS.output) as temporary:
            folder=Path(temporary)/'process'
            shutil.copytree(OPTIONS.native_output/'base-process',folder)
            valid=lambda:EVIDENCE.completed_suite(ROOT,ROOT,OPTIONS.manifest,
                OPTIONS.native_output/'base',folder,'base')
            valid()
            original={name:(folder/name).read_bytes() for name in ('result.json','stdout','stderr')}
            def mutation(kind):
                result=json.loads(original['result.json'])
                if kind==0:result['timed_out']=True
                if kind==1:
                    stdout=json.loads(original['stdout']);stdout['controls']=0;write(folder/'stdout',stdout)
                    result['stdout']=EVIDENCE.pin(folder/'stdout')
                if kind==2:
                    (folder/'stderr').write_bytes(original['stderr'].replace(b'... ok',b'... skipped',1))
                    result['stderr']=EVIDENCE.pin(folder/'stderr')
                if kind==3:result['command'][-1]+='-other'
                write(folder/'result.json',result)
                self.reject(valid)
                for name,raw in original.items():(folder/name).write_bytes(raw)
            for index in range(4):mutation(index)

    def test_04_complete_corpus(self):
        contract=EVIDENCE.object_at(ROOT/'native/serde_error_corpus_contract.json')['base']
        with tempfile.TemporaryDirectory(dir=OPTIONS.output) as temporary:
            folder=Path(temporary)/'capture'
            folder.mkdir();shutil.copyfile(OPTIONS.native_output/'base/native-report.json',folder/'native-report.json')
            shutil.copytree(OPTIONS.native_output/'base/corpus',folder/'corpus')
            metadata=EVIDENCE.object_at(folder/'native-report.json')
            valid=lambda:EVIDENCE.corpus_evidence(folder,contract)
            valid()
            def mutation(name, change):
                path=folder/'corpus'/name;raw=path.read_bytes()
                try:
                    path.write_bytes(change(raw));new=copy.deepcopy(metadata)
                    new['corpus']['files'][name]=EVIDENCE.pin(path);write(folder/'native-report.json',new)
                    self.reject(valid)
                finally:path.write_bytes(raw);write(folder/'native-report.json',metadata)
            mutation('cases.bin.gz',lambda raw:gzip.compress(gzip.decompress(raw)[:8]+b'X'+gzip.decompress(raw)[9:]))
            mutation('native-output.bin.gz',lambda raw:gzip.compress(bytes(4)+gzip.decompress(raw)[4:]))
            mutation('cases.jsonl.gz',lambda raw:gzip.compress(gzip.decompress(raw).replace(b'"ordinal":0',b'"ordinal":1',1)))
            mutation('cases.jsonl.gz',lambda raw:gzip.compress(gzip.decompress(raw).split(b'\n',1)[1]))
            mutation('cases.bin.gz',lambda raw:gzip.compress(gzip.decompress(raw)+b'\0'))
            mutation('native-output.bin.gz',lambda raw:raw[:-5])


def main():
    global OPTIONS,EVIDENCE,BASELINE,ACCEPTED
    parser=argparse.ArgumentParser()
    parser.add_argument('--hepta',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--native-output',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    OPTIONS=parser.parse_args()
    for name in ('hepta','manifest','native_output','output'):
        setattr(OPTIONS,name,getattr(OPTIONS,name).resolve())
    OPTIONS.output.mkdir()
    path=ROOT/'scripts/hia_native_serde_error_qualification.py'
    spec=importlib.util.spec_from_file_location('serde_error_evidence_under_test',path)
    EVIDENCE=importlib.util.module_from_spec(spec);sys.modules[spec.name]=EVIDENCE;spec.loader.exec_module(EVIDENCE)
    BASELINE=EVIDENCE.native_evidence(ROOT,OPTIONS.hepta,OPTIONS.manifest,OPTIONS.native_output)
    sources=EVIDENCE.source_bindings(ROOT)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceControls))
    EVIDENCE.same(BASELINE,EVIDENCE.native_evidence(ROOT,OPTIONS.hepta,OPTIONS.manifest,OPTIONS.native_output),'baseline changed')
    ACCEPTED+=1
    EVIDENCE.same(sources,EVIDENCE.source_bindings(ROOT),'sources changed during controls')
    summary=dict(tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses))
    passed=summary==dict(tests_run=4,failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0) and ACCEPTED==2 and REFUSED==16
    report=dict(schema='hepta.runtime.serde-error-evidence-controls.v1',status='PASS' if passed else 'FAIL',
        summary=summary,accepted=ACCEPTED,refused=REFUSED,new_native_calls=0,new_original_calls=0,
        source_unchanged=True,sources=sources)
    write(OPTIONS.output/'result.json',report)
    print(json.dumps({key:report[key] for key in ('schema','status','summary','accepted','refused','new_native_calls','new_original_calls')},sort_keys=True))
    raise SystemExit(0 if passed else 1)


if __name__=='__main__':main()
