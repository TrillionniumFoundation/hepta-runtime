# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Reject altered borrowed requests and receipts; synthetic values are never filesystem evidence."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import struct
import sys

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
REQUEST=b'HRASQ001'+struct.pack('<Q',1)
EFFECT=0xfffffff0
INVALID=0xffffffff
CAPACITY=0xfffffffe
WORK=1048576


def setq(raw,at,value):
    result=bytearray(raw);struct.pack_into('<Q',result,at,value);return bytes(result)


def acknowledge(session,result=0,error=0):
    sequence=struct.unpack_from('<Q',session._workspace,264)[0]
    struct.pack_into('<3Q',session._workspace,320,sequence,result,error)


def advance(session):
    assert session.invoke_raw(REQUEST)[0]==EFFECT
    struct.pack_into('<I',session._workspace,3072+20,1000)
    struct.pack_into('<H',session._workspace,3072+28,0o40700)
    struct.pack_into('<Q',session._workspace,3072+32,123)
    struct.pack_into('<qI',session._workspace,3072+112,-3,999999999)
    struct.pack_into('<qI',session._workspace,3072+96,5,123456789)
    struct.pack_into('<II',session._workspace,3072+136,8,1)
    acknowledge(session);assert session.invoke_raw(REQUEST)[0]==EFFECT
    assert struct.unpack_from('<Q',session._workspace,272)[0]==5
    struct.pack_into('<Q',session._workspace,1024+144,1000)
    acknowledge(session);assert session.invoke_raw(REQUEST)[0]==EFFECT
    assert struct.unpack_from('<Q',session._workspace,272)[0]==101


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('manifest','runtime','output'):parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    sys.path.insert(0,str(args.runtime.resolve(strict=True)/'scripts'))
    from hia_native_loader import NativeModule
    manifest=args.manifest.read_bytes();rows=[];rejects=0
    def reject(name,code,out,state,expected,outcap=160):
        nonlocal rejects
        assert code==expected and out==bytes([0xa7])*outcap,(name,code,expected)
        rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejects+=1
    reply=b'HNSVR001'+struct.pack('<3Q',1,9,7)+bytes(32)+struct.pack('<Q',1)
    with NativeModule(args.manifest,manifest_sha256=SHA(manifest)) as module:
        bad=[('short',REQUEST[:-1],160,WORK,INVALID),('long',REQUEST+b'\0',160,WORK,INVALID),
            ('magic',b'WRONG001'+REQUEST[8:],160,WORK,INVALID),('output',REQUEST,159,WORK,CAPACITY),
            ('workspace',REQUEST,160,WORK-1,CAPACITY)]
        bad.extend(('operation-'+str(n),setq(REQUEST,8,n),160,WORK,INVALID) for n in (0,2,(1<<64)-1))
        for name,wire,outcap,workcap,expected in bad:
            code,out,state=module.invoke_raw(wire,output_capacity=outcap,workspace_capacity=workcap,output_fill=0xa7)
            reject(name,code,out,state,expected,outcap)
        modifications=[(0,0),(8,2),(16,9),(24,1),(32,3073),(40,255),(48,1),(56,1),(64,0),(64,2),(72,1),(80,4096),(88,1)]
        for at,value in modifications:
            with module.session(output_capacity=160,workspace_capacity=WORK) as session:
                assert session.invoke_raw(REQUEST)[0]==EFFECT
                acknowledge(session);struct.pack_into('<Q',session._workspace,256+at,value)
                ctypes.memset(session._output,0xa7,160)
                code,out,state=session.invoke_raw(REQUEST);reject('metadata-receipt-'+str(at)+'-'+str(value),code,out,state,INVALID)
        for name,at,value in (('state-magic',0,1),('sequence',16,2),('phase',8,55)):
            with module.session(output_capacity=160,workspace_capacity=WORK) as session:
                assert session.invoke_raw(REQUEST)[0]==EFFECT;acknowledge(session)
                struct.pack_into('<Q',session._workspace,at,value);ctypes.memset(session._output,0xa7,160)
                code,out,state=session.invoke_raw(REQUEST);reject(name,code,out,state,INVALID)
        children=[('magic',b'WRONG001'+reply[8:]),('short',reply[:-1]),('extra',reply+b'\0'),
            ('kind',setq(reply,8,3)),('cache',setq(reply,64,3)),('watch-digest',setq(reply,32,1)),
            ('fingerprint-first',setq(reply,8,2)),('error-kind',setq(reply,8,0)),
            ('error-zero',b'HNSVR001'+struct.pack('<3Q',0,23,0)+bytes(32)+struct.pack('<Q',1)),
            ('error-overflow',b'HNSVR001'+struct.pack('<3Q',0,23,4096)+bytes(32)+struct.pack('<Q',1))]
        for name,response in children:
            with module.session(output_capacity=160,workspace_capacity=WORK) as session:
                advance(session);ctypes.memmove(ctypes.addressof(session._workspace)+12288,response,len(response))
                acknowledge(session,len(response));ctypes.memset(session._output,0xa7,160)
                code,out,state=session.invoke_raw(REQUEST);reject('namespace-'+name,code,out,state,INVALID)
        for name,at,value in (('request-mutated',8192+8,2),('request-cache-mutated',8192+24,2),('child-errno',336,5),('child-capacity',312,71)):
            with module.session(output_capacity=160,workspace_capacity=WORK) as session:
                advance(session);ctypes.memmove(ctypes.addressof(session._workspace)+12288,reply,len(reply));acknowledge(session,72)
                struct.pack_into('<Q',session._workspace,at,value);ctypes.memset(session._output,0xa7,160)
                code,out,state=session.invoke_raw(REQUEST);reject(name,code,out,state,INVALID)
        for kind in (1,2):
            with module.session(output_capacity=160,workspace_capacity=WORK) as session:
                advance(session)
                answer=reply if kind==1 else b'HNSVR001'+struct.pack('<3Q',2,0,0)+bytes(range(32))+struct.pack('<Q',2)
                ctypes.memmove(ctypes.addressof(session._workspace)+12288,answer,len(answer));acknowledge(session,72)
                code,out,state=session.invoke_raw(REQUEST)
                assert code==160 and out[:8]==b'HRACC001' and struct.unpack_from('<5Q',out,8)==(0,0,0,112,0)
                assert out[48:56]==b'HRAST001' and struct.unpack_from('<6Q',out,56)==(2049,123,(1<<64)-3,999999999,5,123456789)
                assert out[104:160]==answer[8:64] and struct.unpack_from('<Q',state,8)[0]==0
                assert struct.unpack_from('<Q',state,120)[0]==kind
                rows.append(dict(name='synthetic-complete-'+str(kind),code=code,signed_timestamps_preserved=True))
        with module.session(output_capacity=160,workspace_capacity=WORK) as session:
            assert session.invoke_raw(REQUEST)[0]==EFFECT
            acknowledge(session,error=5);assert session.invoke_raw(REQUEST)[0]==EFFECT
            acknowledge(session,error=14);code,out,state=session.invoke_raw(REQUEST)
            assert code==48 and struct.unpack_from('<5Q',out,8)==(23,5,0,0,0)
            assert struct.unpack_from('<Q',state,120)[0]==1
            rows.append(dict(name='synthetic-statx-probe-preserves-first-error',code=code))
    assert args.manifest.read_bytes()==manifest
    result=dict(schema='hepta.request-audit.stamp-controls.v1',status='PASS',checks=len(rows),rejection_controls=rejects,
        synthetic_completion_controls=len(rows)-rejects,cases=rows,manifest_sha256=SHA(manifest),
        original_executed=False,real_filesystem_effects=False,production_activated=False,whole_runtime_replaced=False)
    (args.output/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'},sort_keys=True))


if __name__=='__main__':main()
