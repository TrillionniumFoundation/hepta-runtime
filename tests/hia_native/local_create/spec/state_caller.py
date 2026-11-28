"""Actual caller controls; filesystem completions here are explicitly typed."""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,json,struct,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
Q=lambda n:struct.pack('<Q',n)
U=lambda b,n:struct.unpack_from('<Q',b,n)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
MASK=(1<<64)-1

def main(manifest,destination):
    destination.mkdir(parents=True,exist_ok=False)
    pm=manifest.parent/'path.json'
    cm=manifest.parent/'cache.json'
    module=NativeModule(manifest,manifest_sha256=sha(manifest.read_bytes()))
    paths=NativeModule(pm,manifest_sha256=sha(pm.read_bytes()))
    caches=NativeModule(cm,manifest_sha256=sha(cm.read_bytes()))
    archive=gzip.open(destination/'complete-arrays.bin.gz','wb');rows=[];cases=[];banks=[]
    started=time.monotonic();report=dict(schema='hepta.runtime.local-create-spec-caller-capture.v1',status='RUNNING',typed_filesystem_completions_only=True,actual_kernel_operations=False)

    def invoke(wire,work,ocap=4096):
        before=[b'G'*32+x+b'g'*32 for x in(wire,b'\xa5'*ocap,work)]
        buffers=[ctypes.create_string_buffer(x,len(x))for x in before];arguments=[]
        for buffer,raw in zip(buffers,before):arguments.extend((ctypes.addressof(buffer)+32,len(raw)-64))
        code=module._entry(*arguments);after=[x.raw for x in buffers]
        assert after[0]==before[0]
        for raw in after:assert raw[:32]==b'G'*32 and raw[-32:]==b'g'*32
        body,work=after[1][32:-32],after[2][32:-32]
        if code in(0xffffffff,0xfffffffe):assert before[1:]==after[1:]
        elif code==0xffffffe0:
            assert body[:8]==b'HLCSPFX1' and U(body,8)<=len(body)
            assert body[U(body,8):]==b'\xa5'*(len(body)-U(body,8))
        elif code<0xffff0000:
            assert code>=32 and body[:8]==b'HLCSPR01' and U(body,24)==code-32
            assert body[code:]==b'\xa5'*(len(body)-code)
        else:assert code in(0xfffffff7,0xffffffef,0xffffffee) and body==b'\xa5'*ocap
        rows.append(dict(number=len(rows)+1,role='caller',code=code,capacities=[len(x)-64 for x in before]))
        for raw in before+after:archive.write(Q(len(raw))+raw)
        return code,body,work

    def refusal(wire,work,expect=0xffffffff,ocap=4096):
        code,_,_=invoke(wire,work,ocap);assert code==expect,(code,expect,wire.hex()[:144])

    def cache_call(wire,work):
        before=[b'G'*32+x+b'g'*32 for x in(wire,b'\xa5'*1048608,work)]
        buffers=[ctypes.create_string_buffer(x,len(x))for x in before];arguments=[]
        for buffer,raw in zip(buffers,before):arguments.extend((ctypes.addressof(buffer)+32,len(raw)-64))
        code=caches._entry(*arguments);after=[x.raw for x in buffers]
        assert after[0]==before[0] and code<0xffff0000
        for raw in after:assert raw[:32]==b'G'*32 and raw[-32:]==b'g'*32
        body=after[1][32:-32];assert body[:8]==b'HVCAR001' and body[code:]==b'\xa5'*(1048608-code)
        rows.append(dict(number=len(rows)+1,role='cache',code=code,capacities=[len(x)-64 for x in before]))
        for raw in before+after:archive.write(Q(len(raw))+raw)
        return code,body,after[2][32:-32]

    def path_call(wire,capacity):
        before=[b'G'*32+x+b'g'*32 for x in(wire,b'\xa5'*capacity,bytes(4096))]
        buffers=[ctypes.create_string_buffer(x,len(x))for x in before];args=[]
        for buffer,raw in zip(buffers,before):args.extend((ctypes.addressof(buffer)+32,len(raw)-64))
        code=paths._entry(*args);after=[x.raw for x in buffers]
        assert code==80 and after[0]==before[0]
        for raw in after:assert raw[:32]==b'G'*32 and raw[-32:]==b'g'*32
        body=after[1][32:-32];extent=U(body,16)
        assert 80<=extent<=capacity and body[extent:]==b'\xa5'*(capacity-extent)
        rows.append(dict(number=len(rows)+1,role='path',code=code,capacities=[len(x)-64 for x in before]))
        for raw in before+after:archive.write(Q(len(raw))+raw)
        return code,body,after[2][32:-32]

    def run(path=b'x',content=b'abc',context=1,exists=False,parent_exists=False,
            mkdir=(0,0),write=(0,0),key=b'/typed/key',cache_value=0,cancel=None,small=False):
        wire=b'HLCSPQ01'+struct.pack('<7Q',1,context,len(path),len(content),123,0,0)+path+content
        work=bytearray(512);work[112:120]=Q(cancel=='initial');work=bytes(work)
        current=wire;ocap=0 if small else 4096;effects=[];growths=0;parent=b''
        _,_,cache=cache_call(b'HVCACH01'+bytes(40),bytes(2*1048576))
        while True:
            code,body,work=invoke(current,work,ocap)
            if code==0xffffffef:
                need=U(work,104);assert need>len(work)
                work+=bytes(need+17-len(work));growths+=1;continue
            if code==0xffffffee:
                need=U(work,136);assert need>ocap
                ocap=need if small else max(ocap,need);growths+=1;continue
            if code==0xfffffff7:
                assert cancel in('initial','mkdir','write');break
            if code!=0xffffffe0:
                assert code<0xffff0000,(code,effects)
                outcome=U(body,16);message=body[32:code]
                if not exists and mkdir==(0,0) and write==(0,0):
                    assert outcome==0 and message==f'File created successfully with {len(content)} bytes'.encode()
                    assert effects[-2:]==[5,6]
                    cached=b'HVCACH01'+struct.pack('<5Q',1,0,len(key),0,0)+key
                    returned,out,_=cache_call(cached,cache)
                    expected=content.replace(b'\r\n',b'\n');present=context==1 and len(expected)<=1048576
                    assert U(out,8)==present and out[32:returned]==(expected if present else b'')
                else:
                    assert outcome==1 and 6 not in effects
                    if mkdir!=(0,0):
                        prefix=b"Permission denied. Cannot create directories: Failed to create dirs for '"+parent.decode('utf-8','replace').encode()+b"': "
                        assert message.startswith(prefix),(message,prefix)
                break
            child=U(body,16);sequence=U(body,24);generation=U(body,32)
            request=body[64:U(body,8)];assert len(request)==U(body,48) and generation==123
            assert U(body,40)=={3:3,4:5}.get(child,1) and U(body,56)==0
            effects.append(child)
            if child==1:
                present=exists if effects==[1]else parent_exists
                result=b'HFLRO001'+struct.pack('<4Q',1,0,8,present);ret=40
            elif child==2:
                ret,out,_=path_call(request,80+len(path))
                assert ret==80;result=out[:U(out,16)];parent=result[80:]
            elif child==3:
                result=b'HSHMKR01'+struct.pack('<3Q',*mkdir,cache_value);ret=32
            elif child==4:
                kind,error=write
                result=b'HLCRER01'+struct.pack('<5Q',48,kind,error,len(content)if kind==0 else min(len(content),1),0);ret=48
            elif child==5:
                result=b'HRLKY001'+struct.pack('<3Q',1,len(key),0)+key;ret=len(result)
            elif child==6:
                ret,out,cache=cache_call(request,cache)
                result=out[:ret]
            elif child==7:
                result=b'HLCMTR01'+Q(cache_value);ret=16
            else:raise AssertionError(child)
            if cancel is not None and cancel=={3:'mkdir',4:'write'}.get(child):ret=0xfffffff7;result=b''
            callback=b'HLCSPC01'+struct.pack('<7Q',2,generation,sequence,child,ret,len(result),0)+result
            banks.append((child,callback,work))
            refusal(current,work)
            current=callback
        cases.append(dict(path_hex=path.hex(),content_bytes=len(content),context=context,exists=exists,
            parent_exists=parent_exists,mkdir=list(mkdir),write=list(write),cancel=cancel,
            effects=effects,growths=growths,code=code,small_output=small))

    try:
        for path in(b'',b'x',b'a/b/x',b'./x',b'../x',b'/x',b'//a///b/x',b'a\xff/b',b'a\0b'):
            for context in(1,2):
                for content in(b'',b'abc',b'A\r\nB\r\r\nC\x00'+chr(0x1f642).encode()):
                    run(path,content,context,write=(2,0)if b'\0'in path else(0,0),small=True)
        for error in(1,2,4,5,9,13,17,20,21,27,28,36,40,122,255,256,999,1000,4095):
            run(b'a/b/x',mkdir=(1,error));run(write=(1,error))
        run(mkdir=(2,0));run(write=(2,0));run(write=(3,0))
        for value in(0,1,2):run(cache_value=value);run(parent_exists=True,cache_value=value)
        run(exists=True);run(b'bad\xff\xfe',exists=True)
        for point in('initial','mkdir','write'):run(cancel=point)
        for size in(4096,1048576,1048577):run(content=b'x'*size,small=True)
        run(content=b'\r\n'*524289,small=True);run(key=b'k'*32768,small=True)
        ordinary=b'HLCSPQ01'+struct.pack('<7Q',1,1,1,3,123,0,0)+b'xabc'
        for length in range(64):refusal(ordinary[:length],bytes(4096))
        for at,values in((0,(0,MASK)),(8,(0,2,MASK)),(16,(0,3,MASK)),(24,(0,2,MASK)),
                          (32,(0,2,4,MASK)),(40,(0,)),(48,(1,MASK)),(56,(1,MASK))):
            for value in values:refusal(ordinary[:at]+Q(value)+ordinary[at+8:],bytes(4096))
        refusal(ordinary+b'x',bytes(4096));refusal(ordinary[:-1]+b'\xff',bytes(4096))
        refusal(ordinary,bytes(511),expect=0xfffffffe)
        refusal(ordinary,bytes(104)+Q(0)+Q(2)+bytes(4096-120))
        for at in range(0,512,8):
            if at not in(104,112,136):refusal(ordinary,bytes(at)+Q(1)+bytes(4096-at-8))
        selected={}
        for child,callback,work in banks:
            if child not in selected and len(work)<32768:selected[child]=(callback,work)
        assert set(selected)==set(range(1,8))
        controls=0
        for child,(callback,work)in sorted(selected.items()):
            for at,values in((0,(0,MASK)),(8,(0,1,3,MASK)),(16,(0,124,MASK)),(24,(0,U(callback,24)+1,MASK)),
                              (32,(0,8,MASK)),(40,(MASK,)),(48,(MASK,len(callback)-63)),(56,(1,MASK))):
                for value in values:refusal(callback[:at]+Q(value)+callback[at+8:],work);controls+=1
            for length in(0,1,7,8,31,63,len(callback)-1):refusal(callback[:length],work);controls+=1
            refusal(callback+b'x',work);controls+=1
            for at,value in((0,0),(24,124),(32,0),(112,2),(120,0),(120,5),(144,0),(144,8),(168,MASK),(176,3)):
                refusal(callback,work[:at]+Q(value)+work[at+8:]);controls+=1
        report.update(status='PASS',calls=len(rows),cases=len(cases),continuation_refusals=controls,
                      elapsed_seconds=time.monotonic()-started,manifest=str(manifest),manifest_sha256=sha(manifest.read_bytes()))
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),calls=len(rows),cases=len(cases),elapsed_seconds=time.monotonic()-started)
        traceback.print_exc();raise
    finally:
        archive.close();module.close();paths.close();caches.close()
        (destination/'rows.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
        (destination/'cases.json').write_text(json.dumps(cases,sort_keys=True,indent=2)+'\n')
        report['artifacts']={p.name:dict(bytes=p.stat().st_size,sha256=sha(p.read_bytes()))for p in destination.iterdir()if p.is_file()}
        (destination/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps(report,sort_keys=True),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();main(args.manifest.resolve(),args.output.resolve())
