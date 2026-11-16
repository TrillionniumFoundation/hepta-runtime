#!/usr/bin/env python3
"""Execute finite real filesystem smoke cases through the exported HIA callable.

This additive development check is not an unchanged-Rust equivalence gate.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess
import time

U64=(1<<64)-1


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def framed(raw): return struct.pack('<Q',len(raw))+raw


def endpoint(value):
    if type(value) is int:
        return struct.pack('<8s3Q',b'HIAEP002',0,0,value & U64)
    if value is None:
        return struct.pack('<8s3Q',b'HIAEP002',3,4,0)+b'null'
    raw=value.encode()
    return struct.pack('<8s3Q',b'HIAEP002',2,len(raw),0)+raw


def request(source,target,display_source,display_target,start,end,append,context=1):
    parts=[bytes(source),bytes(target),display_source.encode(),display_target.encode(),
           endpoint(start),b'' if end is None else endpoint(end),endpoint(append)]
    return struct.pack('<8s15Q',b'HEXTRQ01',1,context,1,*(len(x) for x in parts),0,0,0,0,0)+b''.join(parts)


def responses(raw):
    out=[];at=0
    while at<len(raw):
        assert len(raw)-at>=8
        n=struct.unpack_from('<Q',raw,at)[0];at+=8
        assert n<=len(raw)-at,(n,len(raw)-at,raw[:80])
        out.append(raw[at:at+n]);at+=n
    return out


def cases():
    # name, source bytes/None, existing target bytes/None, start,end,append,wanted,kind
    yield ('crlf_middle',b'first\r\nmiddle\r\nlast\r\n',b'head\r\ntail\r\n',2,2,1,b'head\r\nmiddle\r\ntail\r\n',0)
    yield ('new_directories',b'one\ntwo',None,2,None,0,b'two',0)
    yield ('empty_line',b'\n',None,1,None,-1,b'\n',0)
    yield ('eof_remove_trailing',b'middle',b'head\r\n',1,None,-1,b'head\r\nmiddle',0)
    yield ('start_insert',b'one\ntwo\n',b'tail',1,2,0,b'one\ntwo\ntail',0)
    yield ('missing_source',None,b'untouched',1,None,0,b'untouched',1)
    yield ('zero_source_endpoint',b'a\n',b'untouched',0,None,0,b'untouched',1)
    yield ('reverse_range',b'a\nb\n',b'untouched',2,1,0,b'untouched',1)
    yield ('invalid_append',b'a\n',b'untouched',1,None,-2,b'untouched',1)
    yield ('append_too_far',b'a\n',b'untouched',1,None,2,b'untouched',1)
    yield ('bad_source_utf8',b'\xff',b'untouched',1,None,0,b'untouched',1)
    yield ('invalid_endpoint_text',b'a\n',b'untouched','bad',None,0,b'untouched',1)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--elf',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    result={'schema':'hepta.runtime.extract-callable-smoke.v1','status':'FAIL','cases':[],
        'executable':{'bytes':a.elf.stat().st_size,'sha256':sha(a.elf.read_bytes())},
        'driver_sha256':sha(Path(__file__).read_bytes()),'original_rust_executed':False,
        'fresh_original_compared':False,'public_handler_qualified':False}
    try:
        for name,src,dst,start,end,append,wanted,kind in cases():
            lane=a.output/name;lane.mkdir();work=lane/'work';work.mkdir()
            source=work/'source';target=work/('deep/child/target' if name=='new_directories' else 'target')
            if src is not None:source.write_bytes(src)
            if dst is not None:target.write_bytes(dst)
            wire=request(source.resolve().__fspath__().encode(),target.absolute().__fspath__().encode(),
                'source',str(target.relative_to(work)),start,end,append)
            raw=framed(b'HVCACH01'+bytes(40))+framed(b'HHISTQ01'+bytes(56))+framed(wire)
            (lane/'stdin.bin').write_bytes(raw)
            t=time.monotonic()
            process=subprocess.run([str(a.elf.absolute())],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                cwd=work,timeout=60)
            row={'name':name,'exit_code':process.returncode,'elapsed_seconds':time.monotonic()-t,'deadline_seconds':60,
                'stdin_bytes':len(raw),'stdin_sha256':sha(raw),'stdout_bytes':len(process.stdout),'stdout_sha256':sha(process.stdout),
                'stderr_bytes':len(process.stderr),'stderr_sha256':sha(process.stderr),'status':'FAIL'}
            for label,data in [('stdout',process.stdout),('stderr',process.stderr)]: (lane/(label+'.bin')).write_bytes(data)
            result['cases'].append(row);(a.output/'result.json').write_bytes(canonical(result))
            assert process.returncode==0,(name,process.returncode,process.stdout[-200:])
            answer=responses(process.stdout);assert len(answer)==3,(name,answer)
            assert answer[0]==b'HVCAR001'+bytes(24)
            assert len(answer[1])==64 and answer[1][:8]==b'HHISTR01'
            last=answer[2]
            assert last[:8]==b'HEXTRP01' and len(last)>=32
            op,actual_kind,n=struct.unpack_from('<3Q',last,8)
            assert op==1 and actual_kind==kind and n==len(last)-32,(name,last)
            last[32:].decode('utf-8');row['message']=last[32:].decode('utf-8')
            actual=target.read_bytes() if target.exists() else None
            assert actual==wanted,(name,actual,wanted)
            if actual is not None:(lane/'target.after.bin').write_bytes(actual)
            row['status']='PASS';(lane/'process.json').write_bytes(canonical(row))
        result['status']='PASS'
    except BaseException as e:
        result['error']=repr(e);raise
    finally:
        (a.output/'result.json').write_bytes(canonical(result))
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
