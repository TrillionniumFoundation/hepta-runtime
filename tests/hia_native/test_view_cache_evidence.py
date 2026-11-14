"""Refusal controls over real retained captures; executes zero native requests."""
from __future__ import annotations
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
REFERENCE=Path(os.environ.get('HIA_REFERENCE_RUNTIME',ROOT))
sys.path.insert(0,str(REFERENCE/'scripts'))
sys.path.insert(0,str(ROOT/'scripts'))
from qualify_hia_runtime_native import completed_test_summary
from hia_native_view_cache_qualification import FOLDER,native_evidence

CONTROLS=0


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def replace(path,raw):
    # Snapshots use hard links; retire the private link before a controlled edit.
    path.unlink()
    path.write_bytes(raw)


def write_json(path,value):
    replace(path,(json.dumps(value,indent=2,sort_keys=True)+'\n').encode())


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value=os.environ.get('HIA_CACHE_QUALIFICATION_OUTPUT')
        cls.output=Path(value) if value else Path(os.environ['HIA_BUILD_ROOT']).parent
        cls.report=json.loads((cls.output/'result.json').read_bytes())
        cls.actual=native_evidence(ROOT,cls.output,cls.report,completed_test_summary,reference_root=REFERENCE)

    def snapshot(self):
        temporary=tempfile.TemporaryDirectory(prefix='hia-cache-evidence-')
        output=Path(temporary.name)/'capture'
        shutil.copytree(self.output,output,copy_function=os.link)
        self.addCleanup(temporary.cleanup)
        return output,copy.deepcopy(self.report)

    def refuses(self,output,report,reference=REFERENCE):
        global CONTROLS
        with self.assertRaises((ValueError,KeyError,IndexError,AssertionError)):
            native_evidence(ROOT,output,report,completed_test_summary,reference_root=reference)
        CONTROLS+=1

    def rewrite_capture(self,output,report,metadata):
        write_json(output/FOLDER/'native-corpus.json',metadata)
        raw=(json.dumps(metadata,sort_keys=True)+'\n').encode()
        replace(output/'test_view_cache.py.stdout',raw)
        check=next(v for v in report['checks'] if v['name']=='test_view_cache.py')
        check['summary']=metadata;check['stdout_sha256']=sha(raw);check['stdout_bytes']=len(raw)

    def test_01_real_capture_is_not_new_execution(self):
        self.assertEqual(self.actual['status'],'PASS')
        self.assertEqual(self.actual['native_cases_added_by_replay'],0)
        self.assertEqual(self.actual['captured_native_cases'],13907)
        self.assertFalse(self.actual['shared_concurrency_qualified'])
        self.assertFalse(self.actual['unbounded_storage_qualified'])

    def test_02_incomplete_invocation_refuses(self):
        for mutation in ('missing','exit','timeout','count'):
            output,report=self.snapshot()
            check=next(v for v in report['checks'] if v['name']=='test_view_cache.py')
            if mutation=='missing':report['checks'].remove(check)
            if mutation=='exit':check['exit_code']=1
            if mutation=='timeout':check['timed_out']=True
            if mutation=='count':
                metadata=json.loads((output/FOLDER/'native-corpus.json').read_bytes())
                metadata['counts']['native_elf_requests']=65
                self.rewrite_capture(output,report,metadata)
            self.refuses(output,report)

    def test_03_consistently_rehashed_corpus_refuses(self):
        for name in ('requests.bin.gz','native-output.bin.gz','domains.jsonl.gz'):
            output,report=self.snapshot();path=output/FOLDER/name
            plain=gzip.decompress(path.read_bytes())[:-1]
            raw=gzip.compress(plain,mtime=0);replace(path,raw)
            metadata=json.loads((output/FOLDER/'native-corpus.json').read_bytes())
            metadata['files'][name]={'gzip_sha256':sha(raw),'gzip_bytes':len(raw),
                                    'raw_sha256':sha(plain),'raw_bytes':len(plain)}
            self.rewrite_capture(output,report,metadata)
            self.refuses(output,report)

    def test_04_actual_build_and_elf_refuse_mutation(self):
        output,report=self.snapshot()
        direct=output/report['modules']['view_cache']['manifest']
        receipt=json.loads((direct.parent/'module.receipt.json').read_bytes())
        receipt['source_unchanged']=False
        write_json(direct.parent/'module.receipt.json',receipt)
        self.refuses(output,report)
        output,report=self.snapshot()
        path=output/report['cache_composition']['manifest']
        metadata=json.loads(path.read_bytes());elf=path.parent/'native-local-read.elf'
        content=bytearray(elf.read_bytes())
        at=self.actual['elf_embedding']['images'][1]['image_offset']
        content[at]^=1;replace(elf,content)
        metadata['executable_sha256']=sha(content);metadata['inspection']['sha256']=sha(content)
        write_json(path,metadata);report['cache_composition']['sha256']=sha(path.read_bytes())
        capture=json.loads((output/FOLDER/'native-corpus.json').read_bytes())
        capture['composition']['executable_sha256']=sha(content)
        capture['composition']['manifest_sha256']=sha(path.read_bytes())
        self.rewrite_capture(output,report,capture)
        self.refuses(output,report)
        output,report=self.snapshot()
        proof=json.loads((ROOT/'native/view_cache_composition.json').read_bytes())
        reference=output/'modified-reference';reference.mkdir()
        for name in [*proof['original_sources'],*(v['path'] for v in proof['imports']),'native/view_render.hepta']:
            target=reference/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(REFERENCE/name,target)
        source=reference/'src/mcp/fs/delta.rs'
        replace(source,source.read_bytes()+b'\n// changed original owner\n')
        self.refuses(output,report,reference)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests))
    status=result.wasSuccessful() and result.testsRun==4 and CONTROLS==10
    print(json.dumps({'schema':'hepta.runtime.view-cache-evidence-tests.v1','status':'PASS' if status else 'FAIL',
                      'test_groups':result.testsRun,'refusal_controls':CONTROLS,'native_calls_added':0,
                      'test_sha256':sha(Path(__file__).read_bytes())},sort_keys=True))
    raise SystemExit(0 if status else 1)
