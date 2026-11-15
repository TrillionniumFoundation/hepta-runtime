"""Actual full-span HIA and public typed-boundary execution; locked replay is separate."""
from __future__ import annotations
import collections,ctypes,gzip,hashlib,json,os,shutil,struct,sys,time,unittest
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(os.environ.get('HIA_RUNTIME_ROOT',Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'tests/hia_native'))
from hia_native_loader import NativeModule,NativeRejected,NativeCapacityError
from runtime_mcp_public_capture import Public
from hia_native_span_raw_value_qualification import (
    FOLDER,COUNTS,GROUPS,LEAF_IDENTITY,SDK_REQUEST_IDENTITY,FALSE_FLAGS,compact,sources,pin,
    sdk_cases,initialization,notification,following,expected_capacity_output,public_projection)
from span_raw_value_cases import leaf_cases,large_cases,capacity_cases

class SpanRawValueTests(unittest.TestCase):
    def run(self,result=None):
        result=super().run(result)
        type(self)._suite_failed=not result.wasSuccessful() or bool(result.skipped)
        return result

    @classmethod
    def setUpClass(cls):
        cls._suite_failed=False
        cls.output=Path(os.environ['HIA_RUNTIME_MCP_QUALIFICATION_OUTPUT']).resolve()
        cls.folder=cls.output/FOLDER;cls.folder.mkdir()
        cls.manifest=Path(os.environ['HIA_RUNTIME_MCP_MANIFEST']).resolve()
        cls.metadata=json.loads(cls.manifest.read_bytes());cls.exe=cls.manifest.parent/cls.metadata['elf']
        assert pin(cls.exe.read_bytes())==dict(bytes=cls.metadata['elf_bytes'],sha256=cls.metadata['elf_sha256'])
        row=next(row for row in cls.metadata['members'] if row['name']=='wide_value')
        assert row['source']=='native/serde_json_span.hepta'
        assert hashlib.sha256((ROOT/row['source']).read_bytes()).hexdigest()==row['source_sha256']
        cls.module=NativeModule(Path(row['manifest']),manifest_sha256=row['manifest_sha256'])
        assert cls.module.metadata['image_sha256']==row['image_sha256']
        cls.inputs=sources(ROOT);cls.started=time.perf_counter();cls.counts=collections.Counter();cls.categories=collections.Counter()

    @classmethod
    def tearDownClass(cls):
        cls.module.close()
        unchanged=sources(ROOT)==cls.inputs
        passed=not cls._suite_failed and unchanged and dict(cls.counts)==COUNTS
        result=dict(schema='hepta.runtime.span-raw-value.native.v1',status='PASS' if passed else 'FAIL',groups=GROUPS,
            counts=dict(cls.counts),source_inputs=cls.inputs,leaf_categories=dict(cls.categories),
            manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest(),
            leaf_identity=LEAF_IDENTITY,sdk_requests=SDK_REQUEST_IDENTITY,
            execution=dict(runtime_root=str(ROOT),corpus_root=str(cls.folder),manifest_path=str(cls.manifest)),
            sources_unchanged=unchanged,elapsed_seconds=time.perf_counter()-cls.started,
            live_fixture_reads_required=False,**{flag:False for flag in FALSE_FLAGS})
        (cls.folder/'result.json').write_bytes(compact(result)+b'\n')
        print(compact(result).decode(),flush=True)
        assert unchanged,'span qualification sources changed during execution'

    def test_01_complete_value_map_and_all_byte_tail_domain(self):
        with (self.folder/'requests.hex').open('xb') as requests,(self.folder/'native-output.txt').open('xb') as output,(self.folder/'calls.jsonl').open('xb') as calls:
            for iterator,workspace in [(leaf_cases(),16<<20),(large_cases(),64<<20)]:
                with self.module.session(output_capacity=1<<20,workspace_capacity=workspace) as session:
                    for category,wire,wanted_status,wanted_body in iterator:
                        ctypes.memset(session._output,0xa5,1<<20)
                        header=session.invoke(wire);self.assertEqual(len(header),32);self.assertEqual(header[:8],b'HJSVR002')
                        status,size,needed=struct.unpack('<QQQ',header[8:]);self.assertIn(status,(0,1,5));self.assertEqual(needed,0)
                        body=ctypes.string_at(ctypes.addressof(session._output)+32,size)
                        if status!=0:
                            self.assertEqual(size,0)
                            self.assertEqual(ctypes.string_at(ctypes.addressof(session._output)+32,(1<<20)-32),b'\xa5'*((1<<20)-32))
                        if wanted_status is not None:self.assertEqual((status,body),(wanted_status,wanted_body),(category,wire[:100]))
                        requests.write(wire.hex().encode()+b'\n')
                        code=size if status==0 else 0xffffffff;output.write(f'{code:08x}:'.encode()+body.hex().encode()+b'\n')
                        calls.write(compact(dict(number=self.counts['full_span_cases'],category=category,
                            request_sha256=hashlib.sha256(wire).hexdigest(),header_hex=header.hex(),
                            body_sha256=hashlib.sha256(body).hexdigest(),output_capacity=1<<20,workspace_capacity=workspace))+b'\n')
                        self.categories[category]+=1;self.counts['full_span_cases']+=1;self.counts['actual_native_calls']+=1
        for name,expected in LEAF_IDENTITY.items():self.assertEqual(pin((self.folder/name).read_bytes()),expected)
        self.assertEqual(self.counts['full_span_cases'],COUNTS['full_span_cases'])

    def test_02_exact_growth_refusal_and_same_workspace_recovery(self):
        session=None;group=None
        try:
            with (self.folder/'capacity.jsonl').open('xb') as records:
                for index,spec in enumerate(capacity_cases()):
                    if group!=spec['group']:
                        if session is not None:session.close()
                        session=self.module.session(output_capacity=spec['output_capacity'],workspace_capacity=spec['workspace_capacity'])
                        group=spec['group']
                    self.assertEqual((session.output_capacity,session.workspace_capacity),(spec['output_capacity'],spec['workspace_capacity']))
                    ctypes.memset(session._output,0xa5,spec['output_capacity'])
                    try:result=session.invoke(spec['wire']);code=len(result)
                    except (NativeRejected,NativeCapacityError) as error:code=error.code
                    self.assertEqual(code,spec['code'],(index,spec['group']))
                    raw=ctypes.string_at(ctypes.addressof(session._output),spec['output_capacity'])
                    self.assertEqual(raw,expected_capacity_output(spec),(index,spec['group']))
                    name='capacity/'+str(index)+'.output.bin.gz';path=self.folder/name;path.parent.mkdir(exist_ok=True)
                    path.write_bytes(gzip.compress(raw,mtime=0))
                    records.write(compact(dict(number=index,session_group=spec['group'],input_hex=spec['wire'].hex(),
                        output_capacity=spec['output_capacity'],workspace_capacity=spec['workspace_capacity'],return_code=code,
                        output=dict(path=name,**pin(raw))))+b'\n')
                    self.counts['capacity_and_recovery_controls']+=1;self.counts['actual_native_calls']+=1
        finally:
            if session is not None:session.close()
        self.assertEqual(self.counts['capacity_and_recovery_controls'],COUNTS['capacity_and_recovery_controls'])

    def test_03_actual_public_typed_value_boundaries_and_recovery(self):
        files=self.folder/'files';files.mkdir();(files/'file').write_bytes(b'alpha\nbeta\n')
        cases=sdk_cases(ROOT)
        with (self.folder/'public-cases.jsonl').open('xb') as records,(self.folder/'sdk-requests.hex').open('xb') as requests:
            for index,case in enumerate(cases):
                wire=bytes.fromhex(case['request_hex']);requests.write(case['request_hex'].encode()+b'\n')
                folder=self.folder/'sessions'/str(index);client=Public(folder,self.exe,files);failed=True
                try:
                    initial=client.exchange(initialization());self.assertEqual(json.loads(initial[0])['id'],0)
                    client.exchange(notification(),0)
                    count=1+(case['expected_response'] is not None)
                    lines=client.exchange(wire+b'\n'+following(),count);replies=[json.loads(line) for line in lines]
                    self.assertEqual(replies[-1]['id'],101);self.assertIn('result',replies[-1])
                    if count==2:public_projection(case,replies[0])
                    failed=False
                finally:receipt=client.close(failed)
                records.write(compact(dict(number=index,name=case['name'],process=receipt))+b'\n')
                exchanges=json.loads((folder/'exchanges.json').read_bytes())
                (folder/'exchange-summary.json').write_bytes(compact(dict(exchanges=exchanges))+b'\n')
                self.counts['actual_public_elf_processes']+=1;self.counts['actual_public_elf_responses']+=count+1
                self.counts['actual_sdk_input_cases']+=1
        shutil.rmtree(files)
        self.assertEqual(dict(self.counts),COUNTS)
        self.assertEqual(pin((self.folder/'sdk-requests.hex').read_bytes()),SDK_REQUEST_IDENTITY)

if __name__=='__main__':unittest.main(verbosity=2)
