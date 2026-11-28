#!/usr/bin/env python3
"""Actual HIA typed projection versus retained independently executed Rust SDK.

The JSON Value owner supplies canonical input. This test encodes the private
ABI only; typed values and complete diagnostic text come from original Rust.
"""
from __future__ import annotations
import ctypes, gzip, hashlib, importlib.util, json, os, struct, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
loader=load('_view_params_loader',ROOT/'scripts/hia_native_loader.py')
sdk=load('_view_params_sdk_inputs',Path(__file__).with_name('view_call_oracle')/'sdk_cases.py')
extra=load('_view_params_extra_inputs',Path(__file__).with_name('view_call_oracle')/'parameter_sdk_cases.py')
INVALID,CAPACITY=0xffffffff,0xfffffffe
COUNTS=dict(value_calls=0,projection_calls=0,sessions=0,semantic_cases=0,output_capacity_controls=0,closed_frame_controls=0,workspace_controls=0)
EVENTS=[]; CALLS=None; OUTPUT=None
def sha(raw):return hashlib.sha256(raw).hexdigest()
def frame(raw):return struct.pack('<8s2Q',b'HVPRQ001',len(raw),0)+raw
def json_rows(raw):return [json.loads(line) for line in raw.split(b'\n') if line]
def arguments(encoded):
    text=encoded.decode('utf-8');offset=text.index('"arguments":')+len('"arguments":')
    _,end=json.JSONDecoder().raw_decode(text,offset)
    return text[offset:end].encode('utf-8')
def check_endpoint(raw,value):
    if value is None:assert raw==b'';return
    assert len(raw)>=32 and raw[:8]==b'HIAEP001'
    kind,size,scalar=struct.unpack_from('<3Q',raw,8);assert len(raw)==32+size
    if type(value) is str:assert (kind,scalar,raw[32:])==(2,0,value.encode())
    elif type(value) is int and -(1<<63)<=value<(1<<63):assert (kind,size,scalar)==(0,0,value&((1<<64)-1))
    elif type(value) in (int,float):assert (kind,size,scalar)==(1,0,0)
    else:assert kind==3 and scalar==0 and json.loads(raw[32:])==value
def check_projection(raw,typed):
    assert len(raw)>=96 and raw[:8]==b'HVPRR001'
    status,flags,plen,slen,elen,patlen,clen,context,depth,presence,errorlen=struct.unpack_from('<11Q',raw,8)
    if not typed['ok']:
        assert status==1 and raw[16:88]==bytes(72) and errorlen==len(raw)-96
        assert raw[96:]==typed['error'].encode('utf-8'),(raw[96:],typed['error'])
        return
    value=typed['value'];assert status==0 and errorlen==0
    assert flags==sum(bit for name,bit in [('full',4),('regex',8),('include_hidden',16)] if value[name] is True)
    assert presence==sum(bit for name,bit in [('context',1),('max_depth',2),('pattern',4),('content',8),('full',16),('regex',32),('include_hidden',64)] if value[name] is not None)
    assert (context,depth)==(value['context'] if value['context'] is not None else 0,value['max_depth'] if value['max_depth'] is not None else 0)
    cursor=96
    assert raw[cursor:cursor+plen]==value['path'].encode();cursor+=plen
    check_endpoint(raw[cursor:cursor+slen],value['start']);cursor+=slen
    check_endpoint(raw[cursor:cursor+elen],value['end']);cursor+=elen
    assert raw[cursor:cursor+patlen]==(value['pattern'] or '').encode();cursor+=patlen
    assert raw[cursor:cursor+clen]==(value['content'] or '').encode();cursor+=clen
    assert cursor==len(raw)

def check_shape(raw):
    assert len(raw)>=96 and raw[:8]==b'HVPRR001'
    status,flags,plen,slen,elen,patlen,clen,context,depth,presence,errorlen=struct.unpack_from('<11Q',raw,8)
    assert status in (0,1)
    if status:
        assert raw[16:88]==bytes(72) and errorlen==len(raw)-96;raw[96:].decode('utf-8');return
    assert flags&~28==0 and presence&~127==0 and errorlen==0
    assert 96+plen+slen+elen+patlen+clen==len(raw)
    at=96;raw[at:at+plen].decode('utf-8');at+=plen
    for size in (slen,elen):
        if size:
            endpoint=raw[at:at+size];assert size>=32 and endpoint[:8]==b'HIAEP001'
            kind,length,scalar=struct.unpack_from('<3Q',endpoint,8)
            assert kind in (0,1,2,3) and length==size-32
            if kind in (0,1):assert length==0
            if kind in (1,2,3):assert scalar==0
            if kind==2:endpoint[32:].decode('utf-8')
            if kind==3:json.loads(endpoint[32:])
        at+=size
    raw[at:at+patlen].decode('utf-8');at+=patlen
    raw[at:at+clen].decode('utf-8')

class NativeSession:
    def __init__(self,module,kind,workspace=65536,output=8192):
        self.kind=kind;self.session=module.session(workspace_capacity=workspace,output_capacity=output)
        COUNTS['sessions']+=1;self.sid=COUNTS['sessions']
        EVENTS.append(dict(kind='session_create',session=self.sid,module=kind,workspace=workspace,output=output))
    def invoke(self,wire):
        session=self.session;ctypes.memset(session._output,0xa5,session.output_capacity)
        code,raw,state=session.invoke_raw(wire);COUNTS[self.kind+'_calls']+=1
        call=COUNTS['value_calls']+COUNTS['projection_calls']
        CALLS.write(struct.pack('<8Q',call,1 if self.kind=='value' else 2,self.sid,len(wire),
                                session.workspace_capacity,session.output_capacity,code,len(raw))+wire+raw+state)
        if code>=0xffff0000:assert raw==b'\xa5'*session.output_capacity
        else:assert code<=len(raw)
        return code,raw[:code] if code<0xffff0000 else raw,state
    def close(self):
        EVENTS.append(dict(kind='session_close',session=self.sid));self.session.close()

class ParamsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        location=os.environ.get('HIA_VIEW_PARAMS_REFERENCE_DIR')
        cls.reference=Path(location).resolve() if location else None
        cls.pins={};cls.modules={};cls.rows=[]
        for kind,variable in [('projection','HIA_VIEW_PARAMS_MANIFEST'),('value','HIA_VIEW_PARAMS_VALUE_MANIFEST')]:
            manifest=Path(os.environ[variable]).resolve();meta=json.loads(manifest.read_text())
            cls.modules[kind]=loader.NativeModule(manifest,manifest_sha256=sha(manifest.read_bytes()))
            for path in (manifest,manifest.parent/meta['source'],manifest.parent/meta['image']):cls.pins[str(path)]=sha(path.read_bytes())
        if cls.reference:
            for name in ('sdk-input.jsonl','sdk.stdout','parameter-input.jsonl','parameter.stdout'):
                path=cls.reference/name;cls.pins[str(path)]=sha(path.read_bytes())
        for path in (Path(__file__),Path(loader.__file__),Path(sdk.__file__),Path(extra.__file__)):
            cls.pins[str(path.resolve())]=sha(path.read_bytes())
        if cls.reference:
            assert (cls.reference/'sdk-input.jsonl').read_bytes()==sdk.encode_cases()
            assert (cls.reference/'parameter-input.jsonl').read_bytes()==extra.encoded_cases()
        cls.inputs=[]
        for input_name,output_name,selected,encoded_input in [('sdk-input.jsonl','sdk.stdout',set(range(24)),sdk.encode_cases()),
                ('parameter-input.jsonl','parameter.stdout',set(range(200,239)),extra.encoded_cases())]:
            references={row['case_id']:row for row in json_rows((cls.reference/output_name).read_bytes())} if cls.reference else None
            seen=set()
            for encoded in encoded_input.split(b'\n'):
                if not encoded:continue
                row=json.loads(encoded);cid=row['case_id']
                if cid not in selected:continue
                typed=None
                if references:
                    ref=references[cid];assert ref['name']==row['name'] and len(ref['handler_observations'])==1
                    typed=ref['handler_observations'][0]['typed'];assert type(typed['ok']) is bool
                cls.inputs.append(dict(case_id=cid,name=row['name'],input=arguments(encoded),typed=typed));seen.add(cid)
            assert seen==selected
        assert len(cls.inputs)==63
    @classmethod
    def tearDownClass(cls):
        for item in cls.modules.values():item.close()
        assert cls.pins=={path:sha(Path(path).read_bytes()) for path in cls.pins}

    def test_01_real_value_then_original_typed_projection(self):
        value=NativeSession(self.modules['value'],'value',workspace=1<<20)
        projection=NativeSession(self.modules['projection'],'projection')
        try:
            for row in self.inputs:
                raw=row['input'];vcode,canonical,_=value.invoke(b'HSJVAL01'+struct.pack('<2Q',1,len(raw))+raw)
                self.assertEqual(vcode,len(canonical))
                code,result,_=projection.invoke(frame(canonical));self.assertEqual(code,len(result))
                check_shape(result)
                if row['typed'] is not None:check_projection(result,row['typed'])
                self.rows.append(dict(case_id=row['case_id'],name=row['name'],input_hex=raw.hex(),
                    canonical_hex=canonical.hex(),output_hex=result.hex(),original_typed=row['typed']))
                COUNTS['semantic_cases']+=1
        finally:projection.close();value.close()
        self.assertEqual(len(self.rows),63)
        (OUTPUT/'semantic-cases.jsonl').write_text(''.join(json.dumps(row,sort_keys=True,ensure_ascii=False,allow_nan=False)+'\n' for row in self.rows))

    def test_02_exact_and_short_output_capacities(self):
        self.assertEqual(len(self.rows),63)
        for row in self.rows:
            expected=bytes.fromhex(row['output_hex']);wire=frame(bytes.fromhex(row['canonical_hex']))
            for capacity in (0,len(expected)-1,len(expected)):
                session=NativeSession(self.modules['projection'],'projection',output=capacity)
                try:
                    code,raw,_=session.invoke(wire)
                    if capacity<len(expected):self.assertEqual(code,CAPACITY)
                    else:self.assertEqual((code,raw),(len(expected),expected))
                    COUNTS['output_capacity_controls']+=1
                finally:session.close()

    def test_03_closed_frames_and_insufficient_workspace(self):
        valid=frame(b'{}')
        bad=[valid[:n] for n in (0,7,8,15,16,23,24,25)]
        bad += [b'badmagic'+valid[8:],valid[:16]+struct.pack('<Q',1)+valid[24:],
                valid[:8]+struct.pack('<Q',0)+valid[16:],valid[:8]+struct.pack('<Q',(1<<64)-1)+valid[16:],
                valid+b'x',frame(b'[]'),frame(b'null')]
        session=NativeSession(self.modules['projection'],'projection')
        try:
            for wire in bad:
                code,_,_=session.invoke(wire);self.assertEqual(code,INVALID);COUNTS['closed_frame_controls']+=1
        finally:session.close()
        for capacity in (0,1,32767):
            session=NativeSession(self.modules['projection'],'projection',workspace=capacity)
            try:
                code,_,workspace=session.invoke(valid)
                self.assertEqual(code,CAPACITY);self.assertEqual(workspace,bytes(capacity));COUNTS['workspace_controls']+=1
            finally:session.close()

def main():
    global OUTPUT,CALLS
    OUTPUT=Path(os.environ['HIA_VIEW_PARAMS_CAPTURE_DIR']).resolve();OUTPUT.mkdir(parents=True,exist_ok=False)
    with (OUTPUT/'raw-calls.bin.gz').open('xb') as underlying:
        with gzip.GzipFile(filename='',fileobj=underlying,mode='wb',mtime=0) as CALLS:
            result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ParamsTests))
    (OUTPUT/'sessions.json').write_text(json.dumps(EVENTS,sort_keys=True,indent=2)+'\n')
    summary=dict(schema='hepta.runtime.view-params-native.v1',
        status='NATIVE_COMPLETE_RUST_REPLAY_REQUIRED' if result.wasSuccessful() else 'FAIL',
        groups=result.testsRun,failures=len(result.failures),errors=len(result.errors),counts=COUNTS,
        formal_sdk_typed_cases=24,additional_typed_cases=39,fresh_rust_processes=0,
        qualification_inputs=getattr(ParamsTests,'pins',{}),raw_calls_sha256=sha((OUTPUT/'raw-calls.bin.gz').read_bytes()),
        real_serde_value_owner=True,optional_existing_original_comparison=bool(getattr(ParamsTests,'reference',None)),
        actual_router_qualification=False,whole_view_replaced=False,whole_runtime_replaced=False)
    (OUTPUT/'result.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    print(json.dumps(summary,sort_keys=True),flush=True)
    return not result.wasSuccessful()

if __name__=='__main__':raise SystemExit(main())
