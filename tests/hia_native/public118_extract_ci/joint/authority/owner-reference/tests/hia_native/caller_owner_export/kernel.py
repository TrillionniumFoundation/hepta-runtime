"""Actual fixed native ELF processes; no interpreter inside the executable."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import encoded,put,read,require,sha,source_evidence
from cases import TOKEN,GOOD,FORBIDDEN,UNAUTHORIZED,wire
from execution import execute,LIMITS

def run(args):
    if args.source_pins_sha256 is not None:source_evidence(args.source_root,args.source_pins_sha256)
    args.output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(read(args.manifest))
    executable=args.manifest.parent/manifest['executable']
    binary=read(executable);require(sha(binary)==manifest['executable_sha256'],'native ELF identity')
    originals=[];expected=[];rows=[]
    fixture=args.output/'owned-fixture';fixture.mkdir(mode=0o700)
    try:
        for index,mode in enumerate((2,1),101):
            label='kernel-http' if mode==2 else 'kernel-stdio'
            headers=GOOD if mode==2 else []
            requests=[(0,headers),(3,headers),(3,headers),(1,headers),(3,[]),(3,headers+[(b'origin',b'null')])]
            stdin=b''.join(wire(op,h)+b'\n' for op,h in requests)
            put(args.output/(label+'.stdin'),stdin)
            token=fixture/(label+'-token');token.write_bytes(TOKEN+b'\n');token.chmod(0o600)
            command=[executable,'--authority-http-token',token] if mode==2 else [executable,'--authority-stdio']
            LIMITS[label]=60
            receipt=execute(args.output,label,command,cwd=fixture,env=dict(os.environ),stdin=args.output/(label+'.stdin'))
            stdout=read(args.output/'processes'/(label+'.stdout'))
            require(read(args.output/'processes'/(label+'.stderr'))==b'','native ELF stderr')
            lines=stdout.splitlines(keepends=True);require(len(lines)==6 and all(x.endswith(b'\n') for x in lines),'native complete line stream')
            decoded=[bytes.fromhex(x[:-1].decode()) for x in lines]
            require(all(len(x)>=4 and x.hex().encode()+b'\n'==line for x,line in zip(decoded,lines,strict=True)),'native canonical transport')
            first=decoded[1][4:]
            require(len(first)==80 and first[:8]==b'HROWR001' and struct.unpack_from('<Q',first,8)[0]==int(mode==2),'native projected scope shape')
            owner=first[16:].decode();require(len(owner)==64 and all(c in '0123456789abcdef' for c in owner),'native complete owner bytes')
            if mode==2:require(owner==hashlib.sha256(b'hepta-runtime/private-operator-credential/v1\0'+TOKEN).hexdigest(),'native actual credential projection')
            start={'context':index,'operation':'start','mode':mode,'token_file_hex':(TOKEN+b'\n').hex(),
                'file_mode':0o600,'entropy_seed':7,'entropy_fail':0,'owner_failure':False,'missing_file':False,
                'code':0,'output_hex':''}
            if mode==1:start.update(stdio_fallback_source='native-os-observation',observed_stdio_fallback=owner)
            originals.append(start);expected.append({'context':index,'code':0,'output_hex':'','binding':None})
            state=None
            for ordinal,((op,h),actual) in enumerate(zip(requests,decoded,strict=True)):
                status=UNAUTHORIZED if mode==2 and ordinal==4 else FORBIDDEN if mode==2 and ordinal==5 else 0
                body=b'' if status or op==0 else bytes((int(mode==2),)) if op==1 else first
                require(actual==struct.pack('<I',status)+body,'native complete result differs')
                if not status and op!=0:state={'owner':owner,'authenticated':mode==2}
                row={'context':index,'operation':'request','request_op':op,'headers':[[a.hex(),b.hex()] for a,b in h],
                    'payload_hex':'','code':status,'output_hex':body.hex()}
                originals.append(row);expected.append({'context':index,'code':status,'output_hex':body.hex(),'binding':state})
            originals.append({'context':index,'operation':'shutdown','code':0,'output_hex':''})
            expected.append({'context':index,'code':0,'output_hex':'','binding':None})
            rows.append({'label':label,'mode':mode,'context':index,'pid':receipt['pid'],'requests':6,
                'input_sha256':sha(stdin),'output_sha256':sha(stdout),'owner':owner,'authenticated':mode==2})
            require(read(executable)==binary and read(token)==TOKEN+b'\n','runtime source/fixture changed')
        put(args.output/'original-input.jsonl',b''.join((json.dumps(r,sort_keys=True,separators=(',',':'))+'\n').encode() for r in originals))
        put(args.output/'expected-original.jsonl',b''.join((json.dumps(r,sort_keys=True,separators=(',',':'))+'\n').encode() for r in expected))
        report={'schema':'hepta.runtime.owner-export.kernel.v2','status':'PASS','pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgid(0),
            'rows':rows,'original_rows':16,'requests':12,'executable_sha256':sha(binary),'runtime_python_required':False,
            'current_http_listener_qualified':False,'public_route_qualified':False}
        put(args.output/'summary.json',report)
        if args.source_pins_sha256 is not None:source_evidence(args.source_root,args.source_pins_sha256)
        print(encoded(report).decode(),end='')
    finally:
        for p in fixture.iterdir():
            require(p.is_file() and not p.is_symlink(),'owned kernel fixture changed kind');p.unlink()
        fixture.rmdir()

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('source-root','manifest','output'):p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--source-pins-sha256')
    run(p.parse_args())
