"""Additive bounded ABI, ASCII/UTF-8 and same-session recovery controls."""
from __future__ import annotations
import argparse
import copy
import ctypes
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import read_catalog as reader
import qualify_catalog_policy as capture

def cases():
    valid = capture.framed(2, 0, 0, b'{"properties":{"x":{"type":["null","string"]}},"format":"remove"}')
    rows = []
    def add(label, wire, outcome, oc=32768, wc=65536):
        rows.append({"label":label,"wire":wire,"outcome":outcome,"output_capacity":oc,"workspace_capacity":wc})
    for length in range(64):
        add(f"short-frame-{length}",valid[:length],"invalid")
    for offset in range(8):
        wire=bytearray(valid);wire[offset]^=1;add(f"magic-{offset}",bytes(wire),"invalid")
    for offset, values in ((8,(0,4,2**64-1)),(16,(1,2,4,16,2**64-1)),(24,(1,2,2**64-1)),(32,(0,1,len(valid),2**64-1)),(40,(1,)),(48,(1,)),(56,(1,))):
        for value in values:
            wire=bytearray(valid);struct.pack_into('<Q',wire,offset,value);add(f"field-{offset}-{value}",bytes(wire),"invalid")
    for capacity in (1,7,8,63):
        add(f"short-output-{capacity}",valid,"short-output",oc=capacity)
    for capacity in (1,7,1023,16383):
        add(f"short-workspace-{capacity}",valid,"workspace",wc=capacity)
    for index,body in enumerate((b'',b'{',b'[]',b'null',b'{"x":}',b'{"x":1,}',b'{"x":[1,]}',b'{"x":01}',b'{"x":1.}',b'{"x":1e}',b'{"x":true false}',b'{}x',b'{"x":"\\uD800"}',b'{"x":"\\uDC00"}',b'{"x":"\\uD800\\u0041"}',b'{"x":"\xc0\x80"}',b'{"x":"\xed\xa0\x80"}',b'{"x":"\xf4\x90\x80\x80"}')):
        add(f"syntax-{index}",capture.framed(2,0,0,body),"json-refusal")
    for byte in range(256):
        body=b'{"x":"'+bytes((byte,))+b'"}'
        valid_byte=32<=byte<=127 and byte not in (34,92)
        add(f"ascii-byte-{byte:03d}",capture.framed(2,0,0,body),"schema" if valid_byte else "json-refusal")
    examples=[
        {"type":["null","string"],"anyOf":[{"type":"null"},{"type":"integer"}],"format":"uuid"},
        {"x":{"type":["null",None]}},
        {"x":{"anyOf":[{"type":"null"},{"type":"integer","description":"inner"}],"description":"outer"}},
        {"x":{"anyOf":[{"oneOf":[{"type":"null"},{"type":["null","string"]}]}]}},
        {"properties":{"format":{"format":"remove","default":None},"$schema":{"type":["null","string"]},"default":{"default":7}}},
        {"$defs":{"format":{"format":"remove"}},"x":[[{"format":"keep","type":["null","string"]}],{"format":"remove"}]},
        {"x":{"anyOf":[],"oneOf":[1],"type":[]}},
        {"x":{"anyOf":[{"type":"null"},{"type":"null"}]}},
        {"x":{"type":["null","null","string","integer"]}},
        {"x":"ASCII"*2048,"λ":"🙂","nul":"\u0000"},
    ]
    for index,value in enumerate(examples):
        for mode in (2,3):add(f"policy-{index}-{mode}",capture.framed(mode,0,0,reader.schema_body(value)),"schema")
    for index,body in enumerate((b'{"x":{"type":["null","string"],"t\\u0079pe":["null","integer"]}}',b'{"propert\\u0069es":{"x":{"fo\\u0072mat":"remove"}}}',b'{"x":"\\uD83D\\uDE42","y":"\\u0061"}')):
        add(f"decoded-key-{index}",capture.framed(2,0,0,body),"schema")
    for depth in (1,2,126,127,128):
        body=b'{"x":'+b'['*depth+b'0'+b']'*depth+b'}'
        add(f"depth-{depth}",capture.framed(2,0,0,body),"schema" if depth<128 else "json-refusal")
    add('same-session-first',valid,'schema')
    add('same-session-refusal',capture.framed(2,0,0,b'{"x":}'),'json-refusal')
    add('same-session-recovery',valid,'schema')
    return rows

def expected(row, reference):
    outcome=row['outcome'];wire=row['wire'];mode,flags,modern=struct.unpack_from('<3Q',wire,8) if len(wire)>=32 else (0,0,0)
    if outcome=='invalid':return 4294967295,None
    if outcome=='short-output':return 4294967294,None
    if outcome=='workspace':return 64,b'HCATCR01'+struct.pack('<7Q',2,0,16384,0,flags,modern,0)
    if outcome=='json-refusal':return 64,b'HCATCR01'+struct.pack('<7Q',1,0,0,0,flags,modern,0)
    value=json.loads(wire[64:]);result=copy.deepcopy(value)
    if mode==2:
        for child in result.values():reference.strip_null(child)
        reference.strip_noise(result)
    return None,result

def run(source,build,runtime,output):
    output.mkdir(parents=True,exist_ok=False)
    module=capture.load_module(build/'modules/catalog-policy/manifest.json',runtime)
    reference=reader.reference_module(source)
    records=[]
    session=None
    try:
        for index,row in enumerate(cases()):
            retained=row['label'].startswith('same-session-')
            if retained:
                if session is None:
                    session=module.session(output_capacity=row['output_capacity'],workspace_capacity=row['workspace_capacity'])
                    ctypes.memset(session._output,0xA7,row['output_capacity']);ctypes.memset(session._workspace,0x59,row['workspace_capacity'])
                before_output=session._output.raw[:row['output_capacity']]
                before_work=session._workspace.raw[:row['workspace_capacity']]
                code,out,work=session.invoke_raw(row['wire'])
            else:
                before_output=bytes((0xA7,))*row['output_capacity'];before_work=bytes((0x59,))*row['workspace_capacity']
                code,out,work=module.invoke_raw(row['wire'],output_capacity=row['output_capacity'],workspace_capacity=row['workspace_capacity'],output_fill=0xA7,workspace_fill=0x59)
            prefix=f'control-{index:03d}'
            record=capture.child_record(output,prefix,row['wire'],code,out,work,len(out),len(work))
            record.update({'label':row['label'],'outcome':row['outcome'],'same_session':retained})
            records.append(record)
            want,semantic=expected(row,reference)
            if want in (4294967295,4294967294):
                assert code==want and out==before_output and work==before_work,row['label']
            elif want==64:
                assert code==64 and out[:64]==semantic and out[64:]==before_output[64:],row['label']
                if row['outcome']=='workspace':assert work==before_work,row['label']
            else:
                assert 64<=code<=len(out) and out[:8]==b'HCATCR01' and struct.unpack_from('<7Q',out,8)==(0,64,code-64,1,0,0,0),row['label']
                assert json.loads(out[64:code])==semantic and out[code:]==before_output[code:],row['label']
        result={'schema':'hepta.runtime.catalog-policy-controls.v1','status':'PASS','cases':len(records),'actual_native_calls':len(records),'records':records,'ordinary_target_domain_unchanged':True,'fresh_original_build':False,'whole_runtime_replaced':False}
        capture.dump(output/'result.json',result)
        return result
    finally:
        if session is not None:session.close()
        module.close()

def main():
    p=argparse.ArgumentParser()
    for name in ('source','build','runtime','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    try:r=run(a.source,a.build,a.runtime,a.output)
    except BaseException as e:
        if a.output.is_dir():capture.dump(a.output/'failure.json',{'type':type(e).__name__,'message':str(e)})
        raise
    print(json.dumps({k:v for k,v in r.items() if k!='records'},sort_keys=True))

if __name__=='__main__':main()
