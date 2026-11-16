"""Full-buffer old/new read and exists controls plus a separate metadata namespace."""
from pathlib import Path
import argparse,ctypes as C,gzip,hashlib,itertools,json,struct,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
from hia_native_build import NativeBuild
from hia_native_local_text_body_build import FOLDER,verify_build,decode,read
sha=lambda raw:hashlib.sha256(raw).hexdigest()
q=lambda *v:struct.pack('<'+'Q'*len(v),*v)
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]


def grow(session,kind,need):
    assert kind in (1,2)
    field,capacity=('_workspace','workspace_capacity') if kind==1 else ('_output','output_capacity')
    old=getattr(session,field);before=getattr(session,capacity);assert need>before
    size=(need+4095)&-4096;new=C.create_string_buffer(size+16);C.memmove(new,old,before)
    setattr(session,field,new);setattr(session,capacity,size)


def run(modules,frame,content,cache,plan,log,mode=0):
    sessions=[module.session(output_capacity=16,workspace_capacity=2048) for module in modules]
    for s in sessions:C.memset(s._output,0xa7,s.output_capacity)
    offset=0;read_calls=0;open_calls=0;calls=0
    try:
        for step in range(1000):
            values=[s.invoke_raw(frame)for s in sessions];calls+=len(sessions)
            assert all(value==values[0]for value in values[1:]),('legacy entire buffers differ',frame[:64],step)
            code,out,work=values[0]
            log.write(q(len(frame),code,len(out),len(work))+frame+out+work)
            if code==0xffffffef:
                for s in sessions:grow(s,word(work,216),word(work,200))
                continue
            if code==0xffffffe8:
                action=word(work,656)
                if action==0:value=cache
                else:assert action==1;cache=word(work,664);value=0
                for s in sessions:
                    base=C.addressof(s._workspace)+640
                    C.memmove(base+56,q(value),8);C.memmove(base+80,q(1),8)
                continue
            if code==0xfffffff0:
                action=word(work,272);value=error=extra=0;payload=b''
                if action in (1,5):error=plan['first'];extra=0 if error else plan.get('size',len(content))
                elif action in (3,7,10,11):error=plan.get('fallback',0);extra=0 if error else plan.get('size',len(content))
                elif action in (2,12):error=plan.get('probe',14) if action==2 else plan.get('probe_fallback',14)
                elif action==4:
                    open_calls+=1;error=plan.get('open',0)
                    if error==4 and open_calls>1:error=0
                    extra=0 if error else 1
                elif action==8:
                    read_calls+=1
                    if plan.get('read_eintr') and read_calls==2:error=4
                    elif plan.get('read_error') and offset>=17:error=5
                    else:
                        take=min(word(work,296),len(content)-offset,8192 if len(content)>1024 else plan.get('stride',8192))
                        payload=content[offset:offset+take];value=len(payload);offset+=value
                elif action==9:error=plan.get('close',0)
                else:raise AssertionError(('unexpected effect',action))
                for s in sessions:
                    base=C.addressof(s._workspace)
                    if payload:C.memmove(base+word(work,288),payload,len(payload))
                    C.memmove(base+312,q(value,error,extra,1,mode if not error and action in (1,3,10) and word(frame,8)==3 else 0),40)
                continue
            assert code<0xffff0000 and code<=len(out),(code,frame[:64],step)
            return out[:code],calls
        raise AssertionError('bounded effect fixture did not complete')
    finally:
        for s in sessions:s.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--hepta',type=Path,required=True)
    parser.add_argument('--build-root',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,default=ROOT)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=args.source_root.resolve(strict=True);manifest=args.manifest.resolve(strict=True)
    verify_build(manifest,source_root=root)
    output=args.output.resolve();output.mkdir(exist_ok=False)
    builder=NativeBuild(args.hepta,args.build_root)
    old_path=builder.compile('local-text-body-legacy-read',root/FOLDER/'reference_native/local_read_legacy.hepta',
        standalone=None,buffer_profile='history.v1')
    built=decode(read(manifest));row=built['members'][1]
    old=NativeModule(old_path,manifest_sha256=sha(read(old_path)))
    new=NativeModule(manifest.parent/row['manifest'],manifest_sha256=row['manifest_sha256'])
    assert old.metadata['source_sha256']=='f538f3c484922f54d776f757c94b98c66cc616bd4668006b0380530eae72bc12'
    assert new.metadata['source_sha256']=='a4eacfcdae04233097a2d37ae15447b2e6e99dd5325e98b409b4404896786df0'
    plans=[dict(first=0),dict(first=2),dict(first=13,probe=5),dict(first=38),dict(first=38,fallback=13),
        dict(first=0,size=0,open=4,read_eintr=True,stride=17),dict(first=0,size=31,read_error=True,stride=17),dict(first=0,open=13,close=4)]
    contents=[b'',b'a',b'a'*31,b'a'*32,b'a'*97,'cat\U0001f642\r\n'.encode(),b'bad\xff',b'a'*8193]
    paths=[b'file',b'',b'raw-\xff',b'bad\0path',b'long/'+b'x'*129]
    report=dict(status='RUNNING',legacy_cases=0,namespace_controls=0,metadata_cases=0,actual_native_calls=0,
        original_processes=0,old_source=old.metadata['source_sha256'],new_source=new.metadata['source_sha256'],
        complete_output_and_workspace_compared=True,full_body_async_qualified=False)
    started=time.monotonic()
    try:
        with gzip.open(output/'complete-calls.bin.gz','wb',compresslevel=1) as log:
            for ordinal,(op,cache,plan,content) in enumerate(itertools.product((1,2),(0,1,2),plans,contents)):
                path=paths[ordinal%len(paths)];frame=b'HFLRIO01'+q(op,len(path),0,0,0,0,0)+path
                _,count=run([old,new],frame,content,cache,plan,log)
                report['legacy_cases']+=1;report['actual_native_calls']+=count
            for op in (0,3,4,5,7,15,255,65536,(1<<64)-1):
                frame=b'HFLRIO01'+q(op,1,0,0,0,0,0)+b'x'
                a=old.invoke_raw(frame,output_capacity=97,workspace_capacity=2048,output_fill=0xa7)
                b=new.invoke_raw(frame,output_capacity=97,workspace_capacity=2048,output_fill=0xa7)
                assert a==b and a==(0xffffffff,b'\xa7'*97,bytes(2048))
                log.write(q(len(frame),a[0],len(a[1]),len(a[2]))+frame+a[1]+a[2]);report['namespace_controls']+=1;report['actual_native_calls']+=2
            for op in (0,1,2,4,5,(1<<64)-1):
                frame=b'HFLRMQ01'+q(op,1,0,0,0,0,0)+b'x'
                value=new.invoke_raw(frame,output_capacity=97,workspace_capacity=2048,output_fill=0xa7)
                assert value==(0xffffffff,b'\xa7'*97,bytes(2048));report['namespace_controls']+=1;report['actual_native_calls']+=1
                log.write(q(len(frame),value[0],len(value[1]),len(value[2]))+frame+value[1]+value[2])
            metadata_plans=[(cache,plan) for cache,plan in itertools.product((0,1,2),(dict(first=0),dict(first=38)))]
            metadata_plans.append((0,dict(first=13,probe=5)))
            for (cache,plan),mode in itertools.product(metadata_plans,(0,0o100644,0o40755)):
                frame=b'HFLRMQ01'+q(3,4,0,0,0,0,0)+b'file'
                result,count=run([new],frame,b'1234567',cache,plan,log,mode)
                assert result==b'HFLRO001'+q(3,0,16,7,mode),result
                report['metadata_cases']+=1;report['actual_native_calls']+=count
        report['status']='PASS'
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        old.close();new.close();report['elapsed_seconds']=time.monotonic()-started
        stream=output/'complete-calls.bin.gz';report['stream_bytes']=stream.stat().st_size;report['stream_sha256']=sha(stream.read_bytes())
        (output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
