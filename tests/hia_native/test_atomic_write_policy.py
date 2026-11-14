"""Actual HIA path planning and explicit pure-completion contracts.

The path stream is a lossless replay input for the actual Rust Path owner.
Injected completions exercise policy only and are never counted as OS calls.
"""
from __future__ import annotations
import argparse,gzip,hashlib,itertools,json,os,random,struct,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
if str(HERE) not in sys.path:sys.path.insert(0,str(HERE))
from atomic_write_harness import NativeAtomic,frame,output,sha,INVALID,CAPACITY,STATE,CANCELED
ROOT=HERE.parents[1]

def paths():
    found=set()
    for n in range(8):
        for value in itertools.product(b'./ab',repeat=n):found.add(bytes(value))
    for a in range(256):
        found.add(bytes([a]))
        for b in range(256):found.add(bytes([a,b]))
    for prefix in (b'',b'./',b'//',b'a//./',b'../',b'raw-\xff/'):
        for name in (b'.',b'..',b'...',b'\xf0\x90\x80',b'\xed\xa0\x80',b'\xe2\x82','🙂'.encode(),'é'.encode()):
            for suffix in (b'',b'/',b'/.',b'/..',b'//./'):found.add(prefix+name+suffix)
    rand=random.Random(319)
    for _ in range(1000):found.add(bytes(rand.randrange(256) for _ in range(rand.randrange(3,65))))
    yield from sorted(found)
    for p in (b'a'*(5<<20),b'\xff'*(5<<20),(b'a/./'*10000)+b'z'):
        yield p

def run(manifest,destination):
    destination=Path(destination).resolve();destination.mkdir(mode=0o700)
    native=NativeAtomic(manifest);started=time.monotonic()
    result={'schema':'hepta.runtime.atomic-write-policy-suite.v1','status':'RUNNING','identity':native.identity,
      'path_cases':0,'synthetic_cases':0,'abi_refusals':0,'actual_filesystem_effects':0,'original_rust_status':'PENDING'}
    inputs=hashlib.sha256();outputs=hashlib.sha256();inbytes=0;outbytes=0
    contract_digest=hashlib.sha256();contract_bytes=0;contract_rows=0
    contracts=gzip.open(destination/'contracts.jsonl.gz','wb')
    def retain(domain,wire,observed,details=None):
        nonlocal contract_bytes,contract_rows
        row={k:v for k,v in observed.items() if k not in ('output','workspace')}
        row.update(ordinal=contract_rows,domain=domain,input_hex=wire.hex(),output_hex=observed['output'].hex(),details=details)
        raw=json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n'
        contracts.write(raw);contract_digest.update(raw);contract_bytes+=len(raw);contract_rows+=1
    source_files={p:sha((ROOT/p).read_bytes()) for p in ['native/atomic_write.hepta','native/atomic_write_composition.json','tests/hia_native/atomic_write_harness.py','tests/hia_native/test_atomic_write_policy.py','tests/hia_native/atomic_write_rust_io_properties.txt']}
    try:
        with gzip.open(destination/'path-requests.bin.gz','wb') as requests,gzip.open(destination/'path-native-output.bin.gz','wb') as answers:
            for path in paths():
                request=frame(path,op=2)
                observed=native.run(request)
                assert observed['code']==len(observed['output']) and observed['effects']==[]
                assert observed['output'][:8]==b'HRAWR001' and struct.unpack_from('<Q',observed['output'],8)[0]==2
                framed=struct.pack('<Q',len(request))+request;returned=struct.pack('<I',observed['code'])+observed['output']
                requests.write(framed);answers.write(returned);inputs.update(framed);outputs.update(returned)
                inbytes+=len(framed);outbytes+=len(returned);result['path_cases']+=1
        def success(e,c):
            action=e['action']
            if action in (1,3,10):return (0,0,0o104751)
            if action==11:return (14,0,0)
            if action==4:return (0,0,1)
            if action==5:return (0,e['arg2'],0)
            return (0,0,0)
        properties=(HERE/'atomic_write_rust_io_properties.txt').read_bytes()
        assert sha(properties)=='f88ff140c2c976db5a6c11e8c62fa16957af3205396344eccd43e16aea56bc7d'
        texts={int(k):bytes.fromhex(v) for k,v in (line.split('\t') for line in properties.decode().splitlines())}
        prefixes={1:b"Failed to read metadata for '",2:b"Failed to write temp file for '",3:b"Failed to preserve permissions on '",4:b"Failed to atomically replace '"}
        projections=0
        for stage,action in ((1,1),(2,4),(3,7),(4,8)):
            for error in range(1,4096):
                if (stage==1 and error==2) or (stage in (2,3) and error==4):continue
                def rejected(e,c):
                    if e['action']==action or (action==1 and e['action']==10):return(error,0,0)
                    return success(e,c)
                native.state=1
                observed=native.run(frame(b'target',b'abcdef'),rejected)
                assert observed['output']==output(1,stage,prefixes[stage]+b"target': "+texts[error]),(stage,error,observed)
                retain('errno_projection',frame(b'target',b'abcdef'),observed,{'stage':stage,'error':error})
                result['synthetic_cases']+=1;projections+=1
        result['original_error_display_property_rows']=4095
        result['synthetic_error_projections']=projections
        # Close errors, short writes, real retry boundaries, and cancellation
        # stage semantics are checked against fixed explicit effect sequences.
        wire=frame(b'target',b'abcdef')
        for target in (1,4,5,6,7,8,9):
            for error in (4,5,13,28):
                counts={}
                def completion(e,c):
                    action=e['action'];counts[action]=counts.get(action,0)+1
                    if target==9 and action==8:return(5,0,0)
                    if action==target and counts[action]==1:return(error,0,0)
                    if action==2:return(14,0,0)
                    return success(e,c)
                native.state=0
                observed=native.run(wire,completion)
                actions=[e['action'] for e in observed['effects']]
                assert observed['code']<0xffff0000
                if target in (4,5,7) and error==4:assert counts[target]==2 and observed['output']==output(0)
                if target==6:assert counts[6]==1 and observed['output']==output(0)
                if target==1:assert actions==[1,2]
                if target==8:assert actions[-2:]==[8,9]
                if target==9:assert counts[9]==1
                retain('effect_error',wire,observed,{'target':target,'error':error})
                result['synthetic_cases']+=1
        for stride in (1,2,3):
            def short(e,c):
                if e['action']==5:return (0,min(stride,e['arg2']),0)
                return success(e,c)
            native.state=0;observed=native.run(wire,short)
            assert observed['output']==output(0)
            assert len([e for e in observed['effects'] if e['action']==5])==(6+stride-1)//stride
            retain('short_write',wire,observed,{'stride':stride})
            result['synthetic_cases']+=1
        for action in (1,4,5,6,7,8):
            def cancel(e,c):
                if e['action']==action:c['put'](136,1)
                return success(e,c)
            native.state=0;observed=native.run(wire,cancel)
            assert observed['code']==CANCELED and observed['output']==b''
            if action in (4,5):assert [e['action'] for e in observed['effects']][-1]==6
            retain('cancel',wire,observed,{'action':action})
            result['synthetic_cases']+=1
        invalid=[b'',b'HRAWI001',wire+b'x',b'x'+wire[1:]]
        for index,value in ((8,0),(8,3),(16,(1<<64)-1),(24,(1<<64)-1),(32,1),(40,1),(48,1),(56,1)):
            x=bytearray(wire);struct.pack_into('<Q',x,index,value);invalid.append(bytes(x))
        invalid.append(frame(b'target',b'\xff'))
        for request in invalid:
            native.state=0;observed=native.run(request)
            assert observed['code']==INVALID and observed['output']==b'' and observed['effects']==[]
            retain('invalid_frame',request,observed)
            result['abi_refusals']+=1
        for ocap,wcap in ((0,4096),(1,4096),(128,4096),(4096,0),(4096,1023),(4096,1030)):
            native.state=0;observed=native.run(wire,output_capacity=ocap,workspace_capacity=wcap)
            assert observed['code']==CAPACITY and observed['output']==b'' and observed['effects']==[]
            retain('capacity',wire,observed)
            result['abi_refusals']+=1
        assert source_files=={p:sha((ROOT/p).read_bytes()) for p in source_files}
        result.update(status='PASS',native_calls=native.calls,requests_sha256=inputs.hexdigest(),requests_bytes=inbytes,
          outputs_sha256=outputs.hexdigest(),outputs_bytes=outbytes,source_files=source_files,
          contract_rows=contract_rows,contracts_bytes=contract_bytes,contracts_sha256=contract_digest.hexdigest())
    except BaseException as e:
        result.update(status='FAIL',failure=repr(e));raise
    finally:
        contracts.close();native.close();result['elapsed']=time.monotonic()-started
        (destination/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,default=os.environ.get('HIA_ATOMIC_POLICY_MANIFEST'))
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not a.manifest:p.error('native policy manifest required')
    print(json.dumps(run(a.manifest,a.output),sort_keys=True))
if __name__=='__main__':main()
