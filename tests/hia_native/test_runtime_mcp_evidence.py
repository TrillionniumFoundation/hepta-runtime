"""Physical rejection controls for complete dynamic public MCP evidence.

Only retained bytes are read. Mutations use atomically replaced files in an
isolated copy; neither native nor original implementation is executed.
"""
from __future__ import annotations
import copy,gzip,json,os,shutil,struct,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_runtime_mcp_evidence as q
from hia_native_build import json_bytes
CONTROLS=[]
def encoded(value,*,nonfinite=False):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=nonfinite).encode()+b'\n'
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
        cls.temporary=tempfile.TemporaryDirectory(prefix='runtime-mcp-wide-evidence-')
        cls.output=Path(cls.temporary.name)/'output';cls.output.mkdir()
        for name in cls.baseline['artifact_sha256']:
            target=cls.output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(cls.actual/name,target)
        (cls.output/'outer-control.json').write_bytes(encoded(cls.report))
        cls.source=Path(cls.temporary.name)/'source';cls.source.mkdir()
        for name in ['native/runtime_mcp_sources.json',*cls.baseline['source_binding']['files']]:
            target=cls.source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
        # The copied evidence contains no live fixture tree or authoring tree.
        relocated=q.native_evidence(cls.source,cls.output,cls.report,completed)
        q.exact(relocated,cls.baseline,'two-root/no-live-fixture positive readback differs')
        cls.captured=q.inspect_corpus(ROOT,cls.output/q.FOLDER)
        cls.manifest=cls.report['modules']['runtime_mcp']['manifest']
        cls.bundle=q.decode((cls.output/cls.manifest).read_bytes());cls.folder=Path(cls.manifest).parent
        cls.build_root=cls.output/cls.folder.parent;cls.images={}
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
            with self.assertRaises((ValueError,KeyError,TypeError,AssertionError,EOFError,OSError,UnicodeError,struct.error)):
                action()
            CONTROLS.append(label)
        finally:
            for path,raw in reversed(originals):
                pending=path.with_name(path.name+'.restore');pending.write_bytes(raw);pending.replace(path)
    def json_edit(self,label,name,change,action):
        value=q.decode((self.output/name).read_bytes());change(value)
        self.edits(label,[(name,encoded(value))],action)
    def build_probe(self,report=None,capture=None):
        return q.build_evidence(ROOT,self.output,self.report if report is None else report,q.Evidence(self.output),
                                self.captured['report'] if capture is None else capture)
    def public_probe(self):
        return q.public_cases(ROOT,q.Evidence(self.output),q.FOLDER,self.captured['report'],self.captured['sessions'])
    def private_probe(self):return q.private_refusals(q.Evidence(self.output),q.FOLDER)
    def rows_edit(self,label,name,change,action):
        rows=[q.decode(line) for line in (self.output/name).read_bytes().splitlines()];change(rows)
        self.edits(label,[(name,b''.join(encoded(row) for row in rows))],action)
    def stream_edit(self,label,metadata,index,key,change,action,*,jsonl=False):
        raw=(self.output/metadata).read_bytes()
        value=[q.decode(line) for line in raw.splitlines()] if jsonl else q.decode(raw)
        row=value if index is None else value[index];descriptor=row[key];path=q.FOLDER+'/'+descriptor['path']
        payload=bytearray(gzip.decompress((self.output/path).read_bytes()));change(payload);payload=bytes(payload)
        descriptor.update(bytes=len(payload),sha256=q.sha(payload))
        text=b''.join(encoded(row) for row in value) if jsonl else encoded(value)
        self.edits(label,[(metadata,text),(path,gzip.compress(payload,mtime=0))],action)

    def test_01_actual_process_receipts(self):
        name=q.NATIVE_SUITE
        plans=[('receipt-command',lambda r:r.__setitem__('command',r['command'][:1]+r['command'][2:])),
            ('receipt-bool-exit',lambda r:r.__setitem__('exit_code',False)),
            ('receipt-timeout-budget',lambda r:r.__setitem__('timeout_seconds',181)),
            ('receipt-nonfinite-elapsed',lambda r:r.__setitem__('elapsed_seconds',float('inf'))),
            ('receipt-zero-elapsed',lambda r:r.__setitem__('elapsed_seconds',0)),
            ('receipt-timed-out',lambda r:r.__setitem__('timed_out',True)),
            ('receipt-duplicate',None),('receipt-incomplete-stderr',None)]
        for label,change in plans:
            report=copy.deepcopy(self.report);row=next(r for r in report['checks'] if r['name']==name);edits=[]
            if label=='receipt-duplicate':report['checks'].append(copy.deepcopy(row))
            elif label=='receipt-incomplete-stderr':
                raw=b'\nRan 9 tests in 1.000s\n\nOK\n';row['stderr_bytes']=len(raw);row['stderr_sha256']=q.sha(raw)
                edits=[(name+'.stderr',raw)]
            else:change(row)
            edits.append(('outer-control.json',encoded(report,nonfinite=True)))
            self.edits(label,edits,lambda:q.completed_suite(ROOT,self.output,q.decode((self.output/'outer-control.json').read_bytes()),
                                                          completed,name,q.NATIVE_GROUPS))

    def test_02_sources_and_actual_two_stage_build(self):
        for label,name in [('source-frontend','native/runtime_mcp.hepta'),('source-view-schema','native/view_input_schema.json'),
                           ('source-nfa','native/regex_nfa.hepta'),('source-wide-protocol','native/runtime_mcp_protocol.hepta')]:
            path=self.source/name;raw=path.read_bytes()
            try:
                path.write_bytes(raw+b' ')
                with self.assertRaises(ValueError):q.source_identity(self.source)
                CONTROLS.append(label)
            finally:path.write_bytes(raw)
        for label,change in [
            ('build-compiler-pin',lambda v:v.__setitem__('compiler_commit','0'*40)),
            ('build-fresh-type',lambda v:v['members'][0].__setitem__('fresh_compile','true')),
            ('build-member-origin',lambda v:v['members'][0].__setitem__('manifest','/another/modules/member/manifest.json')),
            ('build-shared-session',lambda v:v['extra_table'].__setitem__(6,'session_context')),
            ('build-shared-view-read',lambda v:v['view_table'].__setitem__(2,'endpoint')),
            ('build-publication-slot',lambda v:v['config_table'].__setitem__(10,'owner'))]:
            value=copy.deepcopy(self.bundle);change(value);raw=encoded(value)
            report=copy.deepcopy(self.report);report['modules']['runtime_mcp']['sha256']=q.sha(raw)
            capture=copy.deepcopy(self.captured['report']);capture['manifest_sha256']=q.sha(raw)
            self.edits(label,[(self.manifest,raw)],lambda:self.build_probe(report,capture))
        origin=Path(self.captured['report']['execution']['manifest_path']).parent.parent
        first=q.mapped_manifest(self.build_root,self.bundle['members'][0]['manifest'],origin)
        receipt=str((first.parent/'module.receipt.json').relative_to(self.output))
        self.json_edit('build-compiler-receipt-bool',receipt,lambda v:v.__setitem__('source_unchanged',1),self.build_probe)
        name=str((first.parent/'module.stderr.log').relative_to(self.output))
        self.edits('build-compiler-raw-stderr',[(name,b'not the actual empty stderr')],self.build_probe)
        linker=q.mapped_manifest(self.build_root,self.bundle['link']['manifest'],origin);lm=q.decode(linker.read_bytes())
        name=str((linker.parent/lm['source']).relative_to(self.output));raw=(self.output/name).read_bytes()
        self.edits('build-upstream-linker-source',[(name,raw+b' ')],self.build_probe)
        for label,filename,offset in [('build-linked-prefix','linked-prefix.elf',245),
                                      ('build-complete-pack-input','pack.input.bin',-1),
                                      ('build-complete-packer-state','pack.workspace.bin',-1),
                                      ('build-complete-elf','runtime-mcp.elf',-1)]:
            name=str(self.folder/filename);raw=bytearray((self.output/name).read_bytes());raw[offset]^=1
            self.edits(label,[(name,bytes(raw))],self.build_probe)
        value=copy.deepcopy(self.bundle);value['link']['actual_return']=True;raw=encoded(value)
        report=copy.deepcopy(self.report);report['modules']['runtime_mcp']['sha256']=q.sha(raw)
        capture=copy.deepcopy(self.captured['report']);capture['manifest_sha256']=q.sha(raw)
        self.edits('build-linker-return-bool',[(self.manifest,raw),(str(self.folder/'link.receipt.json'),encoded(value['link']))],
                   lambda:self.build_probe(report,capture))

    def test_03_complete_public_wire_and_input_binding(self):
        prefix=q.FOLDER+'/'
        self.rows_edit('public-duplicate-view',prefix+'view-cases.jsonl',lambda r:r[1].__setitem__('case_id',0),self.public_probe)
        self.rows_edit('public-cache-session',prefix+'view-cases.jsonl',lambda r:r[-1].__setitem__('session','ordinary-50'),self.public_probe)
        self.rows_edit('public-sdk-fixture-claim',prefix+'router-cases.jsonl',
                       lambda r:r[0].__setitem__('original_fixture_body_text_compared',True),self.public_probe)
        self.rows_edit('public-catalog-fixture-claim',prefix+'info-cases.jsonl',
                       lambda r:r[0].__setitem__('full_original_tool_catalog_compared',True),self.public_probe)
        self.json_edit('public-wide-unbounded-claim',prefix+'wide-case.json',
                       lambda v:v.__setitem__('unrestricted_response_domain_claimed',True),self.public_probe)
        flip=lambda b:b.__setitem__(-1,b[-1]^1)
        self.stream_edit('public-complete-over64-request',prefix+'over64-case.json',None,'actual_request',flip,self.public_probe)
        self.stream_edit('public-complete-over64-body',prefix+'over64-case.json',None,'actual_body',flip,self.public_probe)
        self.rows_edit('public-workdir-scenario',prefix+'workdir-cases.jsonl',
                       lambda r:r[0].__setitem__('scenario_id',-1),self.public_probe)
        self.stream_edit('public-workdir-complete-body',prefix+'workdir-cases.jsonl',0,'actual_body',flip,self.public_probe,jsonl=True)
        def session_probe():
            evidence=q.Evidence(self.output);evidence.source_root=ROOT
            report=q.decode((self.output/(prefix+'result.json')).read_bytes())
            return q.session_streams(evidence,q.FOLDER,report)
        self.json_edit('public-request-budget',prefix+'result.json',
                       lambda v:v['processes'][0].__setitem__('timeout_seconds',61),session_probe)
        name=prefix+'sessions/router-0/exchanges.json'
        self.json_edit('public-exchange-complete-write',name,
                       lambda v:v[0].__setitem__('written_bytes',v[0]['written_bytes']-1),session_probe)
        self.json_edit('public-exchange-complete-response',name,
                       lambda v:v[0]['responses'][0].__setitem__('sha256','0'*64),session_probe)

    def test_04_private_calls_and_delivery_only_buffers(self):
        name=q.FOLDER+'/private/calls.json'
        self.json_edit('private-count',name,lambda r:r.pop(),self.private_probe)
        self.json_edit('private-return-bool',name,lambda r:r[0].__setitem__('return_code',True),self.private_probe)
        self.json_edit('private-capacity-bool',name,lambda r:r[0].__setitem__('workspace_capacity',True),self.private_probe)
        flip=lambda b:b.__setitem__(0,b[0]^1)
        self.stream_edit('private-complete-input',name,4,'input',flip,self.private_probe)
        self.stream_edit('private-complete-before-state',name,4,'workspace_before',flip,self.private_probe)
        self.stream_edit('private-complete-rejected-output',name,4,'output',flip,self.private_probe)
        self.stream_edit('private-real-child-result',name,18,'output',lambda b:b.__setitem__(192,ord('2')),self.private_probe)
        self.stream_edit('private-delivery-replay',name,19,'workspace_after',lambda b:struct.pack_into('<Q',b,280,0),self.private_probe)
        self.stream_edit('private-exact-growth',name,22,'output',lambda b:struct.pack_into('<Q',b,16,127),self.private_probe)

    def test_05_strict_paths_and_complete_packed_machine_bytes(self):
        path=self.output/'strict.json';path.write_bytes(b'{}')
        self.edits('json-duplicate-key',[('strict.json',b'{"status":"PASS","status":"FAIL"}')],lambda:q.decode(path.read_bytes()))
        self.edits('json-nonfinite',[('strict.json',b'{"elapsed":NaN}')],lambda:q.decode(path.read_bytes()))
        with self.assertRaises(ValueError):q.owned(self.output,'../outside')
        CONTROLS.append('path-escape')
        alias=self.output/'alias.json';alias.symlink_to(path)
        with self.assertRaises(ValueError):q.owned(self.output,'alias.json')
        CONTROLS.append('path-symlink')
        elf_name=str(self.folder/'runtime-mcp.elf');obj_name=str(self.folder/'bridge.o')
        elf=(self.output/elf_name).read_bytes();obj=(self.output/obj_name).read_bytes()
        for label,offset,value,width in [('elf-entry-target',239,0,4),('elf-write-execute',68,7,4),
                                         ('elf-image-byte',len(elf)-4096,0,1),('elf-rw-extent',152,1,8)]:
            raw=bytearray(elf)
            if width==1:raw[offset]^=1
            else:struct.pack_into('<I' if width==4 else '<Q',raw,offset,value)
            self.edits(label,[(elf_name,bytes(raw))],lambda:q.elf_structure((self.output/elf_name).read_bytes(),obj,self.images))
        raw=bytearray(obj);shoff=struct.unpack_from('<Q',raw,40)[0]
        sections=[struct.unpack_from('<IIQQQQIIQQ',raw,shoff+i*64) for i in range(8)]
        symbols=next(row for row in sections if row[1]==2);strings=sections[symbols[6]]
        names=bytes(raw[strings[4]:strings[4]+strings[5]])
        changed=False
        for at in range(symbols[4],symbols[4]+symbols[5],24):
            index=struct.unpack_from('<I',raw,at)[0]
            if names[index:names.index(0,index)]==b'_start':
                value=struct.unpack_from('<Q',raw,at+8)[0];struct.pack_into('<Q',raw,at+8,value+1);changed=True;break
        self.assertTrue(changed)
        self.edits('elf-actual-entry-symbol',[(obj_name,bytes(raw))],lambda:q.elf_structure(elf,(self.output/obj_name).read_bytes(),self.images))
        _,symbols=q.object_text(obj);raw=bytearray(elf);at=256+symbols['runtime_grow_view_images']+16
        struct.pack_into('<Q',raw,at,struct.unpack_from('<Q',raw,at)[0]+16)
        self.edits('elf-private-shared-image-address',[(elf_name,bytes(raw))],lambda:q.elf_structure((self.output/elf_name).read_bytes(),obj,self.images))

def main():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceControls))
    count=len(CONTROLS)==q.EVIDENCE_CONTROLS and len(set(CONTROLS))==q.EVIDENCE_CONTROLS
    summary=dict(schema='hepta.runtime.mcp-view-evidence-tests.v2',status='PASS' if result.wasSuccessful() and count else 'FAIL',
        groups=result.testsRun,refusal_controls=len(CONTROLS),controls=sorted(CONTROLS),failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),new_native_calls=0,new_original_processes=0,whole_view_replaced=False,whole_runtime_replaced=False,
        source_and_output_relocation=True,live_fixture_reads_required=False,
        native_evidence_sha256=q.sha(json_bytes(EvidenceControls.baseline)) if hasattr(EvidenceControls,'baseline') else None,
        reader_sha256=q.sha((ROOT/'scripts/hia_native_runtime_mcp_evidence.py').read_bytes()),test_sha256=q.sha(Path(__file__).read_bytes()))
    print(json.dumps(summary,sort_keys=True));raise SystemExit(0 if summary['status']=='PASS' else 1)
if __name__=='__main__':main()
