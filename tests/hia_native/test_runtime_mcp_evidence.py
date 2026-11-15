"""Physical counterexamples for the executed MCP/view evidence reader.

Artifact mutations use a private copy with atomic replacement. Receipt field
controls are decoded again from their physically modified JSON capture.
The admitted native artifacts remain unchanged. No native or Rust call runs.
"""
from __future__ import annotations
import copy
import gzip
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_runtime_mcp_evidence as q
from hia_native_build import json_bytes

CONTROLS=[]
def completed(output,report,name):
    rows=[row for row in report['checks'] if row['name']==name]
    if len(rows)!=1:raise ValueError('actual receipt absent or duplicated')
    return rows[0],q.decode((output/(name+'.stdout')).read_bytes())


class EvidenceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual=Path(os.environ['HIA_RUNTIME_MCP_QUALIFICATION_OUTPUT']).resolve(strict=True)
        cls.report=q.decode((cls.actual/'result.json').read_bytes())
        cls.baseline=q.native_evidence(ROOT,cls.actual,cls.report,completed)
        cls.temporary=tempfile.TemporaryDirectory(prefix='runtime-mcp-evidence-')
        cls.output=Path(cls.temporary.name)/'output';cls.output.mkdir()
        for name in cls.baseline['artifact_sha256']:
            path=cls.output/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(cls.actual/name,path)
        (cls.output/'outer-control.json').write_bytes(q.compact(cls.report)+b'\n')
        cls.captured=q.inspect_corpus(ROOT,cls.output/q.FOLDER)
        cls.manifest=cls.report['modules']['runtime_mcp']['manifest']
        cls.bundle=q.decode((cls.output/cls.manifest).read_bytes())
        cls.folder=Path(cls.manifest).parent
        cls.build_root=cls.output/cls.folder.parent
        cls.images={}
        origin=Path(cls.captured['report']['execution']['manifest_path']).parent.parent
        for row in cls.bundle['members']:
            p=q.mapped_manifest(cls.build_root,row['manifest'],origin);m=q.decode(p.read_bytes())
            cls.images[row['name']]=(p.parent/m['image']).read_bytes()

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def edits(self,label,edits,action):
        originals=[]
        try:
            for name,raw in edits:
                path=self.output/name;originals.append((path,path.read_bytes()))
                pending=path.with_name(path.name+'.mutation');pending.write_bytes(raw);pending.replace(path)
            with self.assertRaises((ValueError,KeyError,TypeError,AssertionError,EOFError,OSError,UnicodeError)):
                action()
            CONTROLS.append(label)
        finally:
            for path,raw in reversed(originals):
                pending=path.with_name(path.name+'.restore');pending.write_bytes(raw);pending.replace(path)

    def json_edit(self,label,name,transform,action):
        value=q.decode((self.output/name).read_bytes());transform(value)
        self.edits(label,[(name,q.compact(value)+b'\n')],action)

    def test_01_actual_process_receipts(self):
        name=q.NATIVE_SUITE
        for label,change in [
            ('receipt-command',lambda row:row.__setitem__('command',row['command'][:1]+row['command'][2:])),
            ('receipt-bool-exit',lambda row:row.__setitem__('exit_code',False)),
            ('receipt-timeout-budget',lambda row:row.__setitem__('timeout_seconds',181)),
            ('receipt-nonfinite-elapsed',lambda row:row.__setitem__('elapsed_seconds',float('inf'))),
            ('receipt-zero-elapsed',lambda row:row.__setitem__('elapsed_seconds',0)),
            ('receipt-timed-out',lambda row:row.__setitem__('timed_out',True)),
            ('receipt-duplicate',None),
            ('receipt-stderr-incomplete',None),
        ]:
            report=copy.deepcopy(self.report);row=next(r for r in report['checks'] if r['name']==name)
            if label=='receipt-duplicate':report['checks'].append(copy.deepcopy(row));edits=[]
            elif label=='receipt-stderr-incomplete':
                raw=b'\nRan 6 tests in 1.000s\n\nOK\n';row['stderr_bytes']=len(raw);row['stderr_sha256']=q.sha(raw);edits=[(name+'.stderr',raw)]
            else:change(row);edits=[]
            physical=json.dumps(report,sort_keys=True,separators=(',',':'),allow_nan=True).encode()+b'\n'
            edits.append(('outer-control.json',physical))
            self.edits(label,edits,lambda:q.completed_suite(ROOT,self.output,q.decode((self.output/'outer-control.json').read_bytes()),completed,name,8))

    def test_02_sources_and_actual_build(self):
        source_root=Path(self.temporary.name)/'source';source_root.mkdir()
        names=['native/runtime_mcp_sources.json',*self.baseline['source_binding']['files']]
        for name in names:
            path=source_root/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,path)
        for label,name in [('source-owner','native/runtime_mcp.hepta'),('source-public-schema','native/view_input_schema.json'),('source-regex-owner','native/regex_controller.hepta')]:
            path=source_root/name;raw=path.read_bytes();pending=path.with_name(path.name+'.changed');pending.write_bytes(raw+b' ');pending.replace(path)
            with self.assertRaises(ValueError):q.source_identity(source_root)
            CONTROLS.append(label);pending.write_bytes(raw);pending.replace(path)
        for label,change in [
            ('build-compiler-pin',lambda value:value.__setitem__('compiler_commit','0'*40)),
            ('build-fresh-claim-type',lambda value:value['members'][0].__setitem__('fresh_compile','true')),
            ('build-member-origin',lambda value:value['members'][0].__setitem__('manifest','/different-origin/modules/member/manifest.json')),
            ('build-regex-selector',lambda value:value['regex_selector_members'].__setitem__('15','publication')),
        ]:
            value=copy.deepcopy(self.bundle);change(value);raw=q.compact(value)+b'\n'
            report=copy.deepcopy(self.report);report['modules']['runtime_mcp']['sha256']=q.sha(raw)
            capture=copy.deepcopy(self.captured['report']);capture['manifest_sha256']=q.sha(raw)
            self.edits(label,[(self.manifest,raw)],lambda:q.build_evidence(ROOT,self.output,report,q.Evidence(self.output),capture))
        origin=Path(self.captured['report']['execution']['manifest_path']).parent.parent
        first=q.mapped_manifest(self.build_root,self.bundle['members'][0]['manifest'],origin)
        receipt=str((first.parent/'module.receipt.json').relative_to(self.output))
        self.json_edit('build-compiler-receipt-bool',receipt,lambda value:value.__setitem__('source_unchanged',1),
            lambda:q.build_evidence(ROOT,self.output,self.report,q.Evidence(self.output),self.captured['report']))
        linker=q.mapped_manifest(self.build_root,self.bundle['linker_manifest'],origin);lm=q.decode(linker.read_bytes())
        name=str((linker.parent/lm['source']).relative_to(self.output));raw=(self.output/name).read_bytes()
        self.edits('build-linker-source',[(name,raw+b' ')],lambda:q.build_evidence(ROOT,self.output,self.report,q.Evidence(self.output),self.captured['report']))
        name=str(self.folder/'runtime-mcp.elf');raw=bytearray((self.output/name).read_bytes());raw[-1]^=1
        self.edits('build-complete-elf',[(name,bytes(raw))],lambda:q.build_evidence(ROOT,self.output,self.report,q.Evidence(self.output),self.captured['report']))

    def public_probe(self):
        return q.public_cases(ROOT,q.Evidence(self.output),q.FOLDER,self.captured['report'],self.captured['sessions'])

    def row_edit(self,label,name,transform):
        raw=(self.output/name).read_bytes();rows=[q.decode(row) for row in raw.splitlines()];transform(rows)
        self.edits(label,[(name,b''.join(q.compact(row)+b'\n' for row in rows))],self.public_probe)

    def test_03_complete_public_wire_and_case_binding(self):
        self.row_edit('public-duplicate-case',q.FOLDER+'/view-cases.jsonl',lambda rows:rows[1].__setitem__('case_id',0))
        self.row_edit('public-cache-session',q.FOLDER+'/view-cases.jsonl',lambda rows:rows[-1].__setitem__('session','ordinary-50'))
        self.row_edit('public-router-fixture-claim',q.FOLDER+'/router-cases.jsonl',lambda rows:rows[0].__setitem__('original_fixture_body_text_compared',True))
        self.row_edit('public-catalog-fixture-claim',q.FOLDER+'/info-cases.jsonl',lambda rows:rows[0].__setitem__('full_original_tool_catalog_compared',True))
        self.json_edit('public-wide-unbounded-claim',q.FOLDER+'/wide-case.json',lambda value:value.__setitem__('unrestricted_response_domain_claimed',True),self.public_probe)
        self.json_edit('regex-state-before-validation',q.FOLDER+'/regex-cases.json',
                       lambda rows:rows[5].__setitem__('state_directory_exists_after',True),self.public_probe)
        self.json_edit('regex-first-error-order',q.FOLDER+'/regex-cases.json',
                       lambda rows:rows[10].__setitem__('kind','first-error-late'),self.public_probe)
        name=q.FOLDER+'/regex-cases.json';rows=q.decode((self.output/name).read_bytes())
        descriptor=rows[0]['initial_config'];path=q.FOLDER+'/'+descriptor['path']
        raw=gzip.decompress((self.output/path).read_bytes())+b' '
        descriptor.update(bytes=len(raw),sha256=q.sha(raw))
        self.edits('regex-complete-initial-config',[(name,q.compact(rows)+b'\n'),(path,gzip.compress(raw,mtime=0))],self.public_probe)
        for label,key in [('public-original-input','original_input'),('public-complete-body','actual_body'),('public-complete-response','actual_response')]:
            name=q.FOLDER+'/view-cases.jsonl';rows=[q.decode(row) for row in (self.output/name).read_bytes().splitlines()]
            descriptor=rows[1][key];path=q.FOLDER+'/'+descriptor['path'];raw=gzip.decompress((self.output/path).read_bytes())+b'x'
            descriptor.update(bytes=len(raw),sha256=q.sha(raw));metadata=b''.join(q.compact(row)+b'\n' for row in rows)
            self.edits(label,[(name,metadata),(path,gzip.compress(raw,mtime=0))],self.public_probe)

    def private_probe(self):return q.private_refusals(q.Evidence(self.output),q.FOLDER)

    def test_04_private_refusals_retain_complete_state(self):
        name=q.FOLDER+'/private-refusals.json'
        for label,change in [
            ('private-count',lambda rows:rows.pop()),
            ('private-return-bool',lambda rows:rows[0].__setitem__('return_code',True)),
            ('private-capacity-bool',lambda rows:rows[0].__setitem__('workspace_capacity',True)),
            ('private-full-state-hash',lambda rows:rows[0].__setitem__('workspace_after_sha256','0'*64)),
        ]:self.json_edit(label,name,change,self.private_probe)
        for label,key in [('private-request-byte','input'),('private-footer-byte','footer_after'),('private-output-byte','output_after')]:
            rows=q.decode((self.output/name).read_bytes());descriptor=rows[4][key];path=q.FOLDER+'/'+descriptor['path'];raw=bytearray(gzip.decompress((self.output/path).read_bytes()));raw[0]^=1;raw=bytes(raw)
            descriptor.update(bytes=len(raw),sha256=q.sha(raw))
            self.edits(label,[(name,q.compact(rows)+b'\n'),(path,gzip.compress(raw,mtime=0))],self.private_probe)
        positive=q.FOLDER+'/private-positives.json'
        self.json_edit('private-actual-child-return',positive,lambda rows:rows[0].__setitem__('return_code',0),self.private_probe)

    def test_05_strict_parsing_paths_and_linked_machine_bytes(self):
        path=self.output/'strict.json';path.write_bytes(b'{}')
        self.edits('json-duplicate-key',[('strict.json',b'{"status":"PASS","status":"FAIL"}')],lambda:q.decode(path.read_bytes()))
        self.edits('json-nonfinite',[('strict.json',b'{"elapsed":NaN}')],lambda:q.decode(path.read_bytes()))
        with self.assertRaises(ValueError):q.owned(self.output,'../outside')
        CONTROLS.append('path-escape')
        alias=self.output/'alias.json';alias.symlink_to(path)
        with self.assertRaises(ValueError):q.owned(self.output,'alias.json')
        CONTROLS.append('path-symlink')
        elf_name=str(self.folder/'runtime-mcp.elf');obj_name=str(self.folder/'runtime.o')
        elf=(self.output/elf_name).read_bytes();obj=(self.output/obj_name).read_bytes()
        for label,offset,value in [('elf-writable-executable',68,7),('elf-interpreter-header',176,3),('elf-padding-byte',len(elf)-1,1)]:
            raw=bytearray(elf)
            if label=='elf-padding-byte':raw[offset]=value
            else:struct.pack_into('<I',raw,offset,value)
            self.edits(label,[(elf_name,bytes(raw))],lambda:q.elf_structure((self.output/elf_name).read_bytes(),obj,self.images))
        raw=bytearray(obj);shoff=struct.unpack_from('<Q',raw,40)[0];rela_offset=struct.unpack_from('<Q',raw,shoff+2*64+24)[0]
        raw[rela_offset+16]^=1
        self.edits('elf-child-relocation',[(obj_name,bytes(raw))],lambda:q.elf_structure(elf,(self.output/obj_name).read_bytes(),self.images))


def main():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceControls))
    require_count=len(CONTROLS)==q.EVIDENCE_CONTROLS and len(set(CONTROLS))==q.EVIDENCE_CONTROLS
    summary=dict(schema='hepta.runtime.mcp-view-evidence-tests.v1',status='PASS' if result.wasSuccessful() and require_count else 'FAIL',groups=result.testsRun,
                 refusal_controls=len(CONTROLS),controls=sorted(CONTROLS),failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
                 new_native_calls=0,new_original_processes=0,whole_view_replaced=False,whole_runtime_replaced=False,
                 native_evidence_sha256=q.sha(json_bytes(EvidenceControls.baseline)) if hasattr(EvidenceControls,'baseline') else None,
                 reader_sha256=q.sha((ROOT/'scripts/hia_native_runtime_mcp_evidence.py').read_bytes()),test_sha256=q.sha(Path(__file__).read_bytes()))
    print(json.dumps(summary,sort_keys=True));raise SystemExit(0 if summary['status']=='PASS' else 1)


if __name__=='__main__':main()
