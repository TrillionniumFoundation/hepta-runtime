#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual HIA admission, finite child-receipt and output atomicity controls.

Child completion bytes in this suite are explicit fixtures. The real installed
configuration and execution chain is tested by the separate ELF process suite.
"""
from pathlib import Path
import argparse,ctypes,hashlib,json,struct,sys,time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(Path(__file__).resolve().parent))
from hia_native_loader import NativeModule,NativeRejected,NativeCapacityError
from public_registry_cases import initialize,request,tool,metadata
sha=lambda b:hashlib.sha256(b).hexdigest()
U=lambda b,p:struct.unpack_from('<Q',b,p)[0]
P=lambda b,p,v:struct.pack_into('<Q',b,p,v)
CALL=0xffffffe0;INVALID=0xffffffff;CAPACITY=0xfffffffe
CHILD=100667392;FOOTER=(256<<20)-256

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();m=json.loads(a.manifest.read_bytes());a.output.mkdir(parents=True,exist_ok=False)
    begun=time.monotonic();r={'status':'RUNNING','elf_sha256':m['elf_sha256'],'native_router_calls':0,'decoder_calls':0,'connection_calls':0,'fixture_child_acks':0,'diagnostic_nonzero_controls':0,'receipt_refusals':0,'envelope_refusals':0,'private_input_refusals':0,'capacity_refusals':0,'groups':[]}
    def save():(a.output/'result.json').write_text(json.dumps(r,sort_keys=True,indent=2)+'\n')
    def module(key):
        member=next(x for x in m['members']if x['name']==key);mp=Path(member['manifest']);assert sha(mp.read_bytes())==member['manifest_sha256'];return NativeModule(mp,manifest_sha256=member['manifest_sha256'])
    def invoke(s,wire):
        r['native_router_calls']+=1
        try:return s(wire)
        except NativeCapacityError:return CAPACITY
        except NativeRejected as error:return error.code
    def current(s,at,count):return ctypes.string_at(ctypes.addressof(s._workspace)+at,count)
    def write(s,at,data):ctypes.memmove(ctypes.addressof(s._workspace)+at,bytes(data),len(data))
    def guard(s):ctypes.memset(s._output,0xa5,s.output_capacity)
    def untouched(s):assert ctypes.string_at(s._output,s.output_capacity)==b'\xa5'*s.output_capacity
    save()
    try:
        with module('message')as mm,module('connection')as cm,module('mcp')as rm:
            with mm.session(output_capacity=2<<20,workspace_capacity=4<<20)as decoder,cm.session(output_capacity=2<<20,workspace_capacity=2<<20)as connection:
                def admit(raw):
                    r['decoder_calls']+=1;projection=decoder(b'HRCJQ001'+struct.pack('<QQ',1,len(raw))+raw)
                    r['connection_calls']+=1;return connection(b'HRCNQ001'+struct.pack('<QQ',1,len(projection))+projection)
                admit(initialize());host=admit(tool('host_list'));catalog=admit(request('tools/list'));badargs=admit(tool('host_list',b'{"\\u0000":0}'));unknown=admit(tool('unknown'))
                modern=admit(tool('host_list',meta=metadata()));execution=admit(tool('execution_shadow_admit'))
            with rm.session(output_capacity=8192,workspace_capacity=256<<20)as s:
                # Every malformed private span is refused before a public byte.
                bad=[b'',host[:255],host[:-1]]
                for at,value in [(0,0),(8,6),(16,1),(24,2),(32,2),(40,2),(48,2),(56,4),(80,0),(80,len(host)),(88,255),(88,1<<63),(160,1)]:
                    changed=bytearray(host);P(changed,at,value);bad.append(bytes(changed))
                projection=U(host,80)
                for at,value in [(0,0),(8,4),(16,20),(24,4),(32,2),(40,0),(56,1),(64,1),(80,0),(88,0),(200,1<<63),(224,1)]:
                    changed=bytearray(host);P(changed,projection+at,value);bad.append(bytes(changed))
                for raw in bad:
                    before=current(s,0,72);guard(s);assert invoke(s,raw)==INVALID;untouched(s);assert current(s,0,72)==before;r['private_input_refusals']+=1
                r['groups'].append('private-header-and-span-before-publication')
                for incoming in [host,modern,execution]:
                    guard(s);assert invoke(s,incoming)==CALL;untouched(s);seq=U(current(s,0,64),8)
                    footer=bytearray(current(s,FOOTER,112));assert U(footer,8)==seq and U(footer,64)==67108864
                    body=b'typed child result\n"\\\x00\xe4\xb8\xad';frame=b'HRCFGM01'+struct.pack('<QQQ',0,0,len(body))+body;write(s,CHILD,frame)
                    P(footer,80,len(frame));P(footer,88,seq);P(footer,96,1)
                    for at,value in [(0,0),(8,seq+1),(16,7),(24,1),(32,0),(40,0),(48,1),(56,0),(64,1),(72,1),(80,31),(80,67108865),(88,seq+1),(96,0),(96,2),(104,1)]:
                        damaged=bytearray(footer);P(damaged,at,value);write(s,FOOTER,damaged);guard(s);assert invoke(s,incoming)==INVALID,(at,value);untouched(s);assert U(current(s,0,8),0)==1;r['receipt_refusals']+=1
                    write(s,FOOTER,footer)
                    for at,value in [(0,0),(8,4),(24,len(body)+1),(24,1<<63)]:
                        damaged=bytearray(frame);P(damaged,at,value);write(s,CHILD,damaged);guard(s);assert invoke(s,incoming)==INVALID;untouched(s);r['envelope_refusals']+=1
                    write(s,CHILD,frame);out=invoke(s,incoming);value=json.loads(out);assert value['result']['content'][0]['text']==body.decode();assert not value['result']['isError'];assert ('resultType'in value['result'])==(incoming==modern);assert U(current(s,0,8),0)==0;r['fixture_child_acks']+=1
                    # Offset 16 is an owner diagnostic, not a reserved word.
                    # It must not replace the original text or reject a valid
                    # nonzero diagnostic from installed-host lookup failures.
                    assert invoke(s,incoming)==CALL
                    footer=bytearray(current(s,FOOTER,112));frame=b'HRCFGM01'+struct.pack('<QQQ',1,42,len(body))+body
                    write(s,CHILD,frame);P(footer,80,len(frame));P(footer,88,U(footer,8));P(footer,96,1);write(s,FOOTER,footer)
                    value=json.loads(invoke(s,incoming));assert value['result']['isError'] and value['result']['content'][0]['text']==body.decode()
                    assert U(current(s,0,8),0)==0;r['fixture_child_acks']+=1;r['diagnostic_nonzero_controls']+=1
                r['groups'].append('fixed-receipts-and-child-envelope-admission')
                out=json.loads(invoke(s,badargs));assert out['result']['isError']and '\x00'in out['result']['content'][0]['text']
                assert json.loads(invoke(s,unknown))['error']['code']==-32602
                assert [x['name']for x in json.loads(invoke(s,catalog))['result']['tools']]==['effective_config','execution_shadow_admit','host_list']
                r['groups'].append('exact-default-errors-and-sorted-real-catalog')
            # One capacity arena is enough to check success/capacity boundaries
            # without copying the 256 MiB owned state into the observer.
            for capacity in [0,1,64,128]:
                with rm.session(output_capacity=capacity,workspace_capacity=256<<20)as s:
                    guard(s);assert invoke(s,catalog)==CAPACITY;untouched(s);assert U(current(s,0,8),0)==0;r['capacity_refusals']+=1
                    assert invoke(s,host)==CALL
                    footer=bytearray(current(s,FOOTER,112));body=b'x'*512;frame=b'HRCFGM01'+struct.pack('<QQQ',0,0,len(body))+body;write(s,CHILD,frame);P(footer,80,len(frame));P(footer,88,U(footer,8));P(footer,96,1);write(s,FOOTER,footer)
                    guard(s);assert invoke(s,host)==CAPACITY;untouched(s);assert U(current(s,0,8),0)==0;r['capacity_refusals']+=1
                    assert invoke(s,host)==CALL and U(current(s,0,64),8)==2
            r['groups'].append('output-measurement-and-next-request-after-capacity')
        r['status']='PASS'
    except BaseException as error:r.update(status='FAIL',error=repr(error));raise
    finally:r['elapsed_seconds']=time.monotonic()-begun;save();print(json.dumps(r,sort_keys=True))
if __name__=='__main__':main()
