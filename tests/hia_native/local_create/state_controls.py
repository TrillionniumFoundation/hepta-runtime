"""Execute actual HIA with typed completions; these are not kernel operations."""
from pathlib import Path
import collections,ctypes,gzip,json,struct,sys,time
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE.parents[2]/'scripts'))
from hia_native_loader import NativeModule
from kernel_cases import frame,sha,MASK
Q=lambda value:struct.pack('<Q',value)
U=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
def word(raw,at,value):return raw[:at]+Q(value)+raw[at+8:]
INVALID,CAPACITY,PENDING=0xffffffff,0xfffffffe,0xfffffffd
guards=((b'i'*16,b'I'*16),(b'o'*16,b'O'*16),(b'w'*16,b'W'*16))

def invoke(wire,work,expected,category,*,outcap=64,unchanged=False):
    output=b'\xa7'*outcap
    initial=(wire,output,work);sizes=[len(value) for value in initial]
    before=[left+value+right for (left,right),value in zip(guards,initial)]
    actual=[ctypes.create_string_buffer(value,len(value)) for value in before]
    args=[]
    for buffer,size in zip(actual,sizes):args.extend((ctypes.addressof(buffer)+16,size))
    started=time.monotonic_ns()
    with module._lock:returned=module._entry(*args)
    elapsed=time.monotonic_ns()-started
    after=[buffer.raw for buffer in actual]
    counts['actual_native_calls']+=1
    assert returned==expected,(category,returned,expected)
    assert after[0]==before[0]
    for raw,(left,right) in zip(after,guards):assert raw[:16]==left and raw[-16:]==right
    result=after[1][16:-16];state=after[2][16:-16]
    if returned==48:assert result[48:]==output[48:]
    else:assert result==output,(category,'nonresult output changed')
    if unchanged or returned in (INVALID,CAPACITY):assert state==work,(category,'refusal/poll changed state')
    if len(wire)>=64:
        extent=513+U(wire,16)+U(wire,24)
        assert state[extent:]==work[extent:]
    row=dict(number=counts['actual_native_calls'],category=category,returned=returned,
             capacities=sizes,elapsed_ns=elapsed,complete_buffers_checked=True)
    rows.write(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
    for raw in before+after:arrays.write(Q(len(raw))+raw)
    return state,result[:48] if returned==48 else b''

def start(data=b'abc',path=b'file',category='start'):
    wire=frame(path,data);work=b'\x5a'*(513+len(path)+len(data)+17)
    work,_=invoke(wire,work,48 if b'\0' in path else PENDING,category)
    return word(wire,8,2),work

def complete(work,error=0,value=0,token=0):
    return work[:184]+struct.pack('<4Q',1,(-error&MASK) if error else value,error,0 if error else token)+work[216:]

def finish(wire,work,kind,error,written,category):
    work,body=invoke(wire,work,48,category)
    assert body==b'HLCRER01'+struct.pack('<5Q',48,kind,error,written,0)
    same,again=invoke(wire,work,48,category+'-replay',unchanged=True)
    assert same==work and again==body
    counts[category]+=1
    return work

def controls():
    for error in range(1,4096):
        if error==4:continue
        wire,work=start(category='open-error-start')
        invoke(wire,work,PENDING,'ready-zero',unchanged=True)
        finish(wire,complete(work,error),1,error,0,'open-errors')
    for error in range(1,4096):
        if error==4:continue
        wire,work=start(category='write-error-start')
        work,_=invoke(wire,complete(work,value=7,token=23),PENDING,'open-success')
        work,_=invoke(wire,complete(work,error),PENDING,'write-error')
        assert U(work,144)==3 and U(work,48)==0 and U(work,88)==23
        finish(wire,complete(work),1,error,0,'write-errors')
    for error in range(4096):
        wire,work=start(data=b'',category='close-error-start')
        work,_=invoke(wire,complete(work,value=7,token=23),PENDING,'empty-open-success')
        finish(wire,complete(work,error),0,0,0,'close-errors-ignored')
    more_controls()

def more_controls():
    for count in (1,2,3,8,64,257):
        wire,work=start(category='retry-start')
        for unused in range(count):work,_=invoke(wire,complete(work,4),PENDING,'open-eintr')
        work,_=invoke(wire,complete(work,value=0,token=MASK),PENDING,'open-after-eintr')
        for unused in range(count):work,_=invoke(wire,complete(work,4),PENDING,'write-eintr')
        work,_=invoke(wire,complete(work,value=1),PENDING,'partial-write')
        assert U(work,56)==1 and U(work,160)==513+4+1 and U(work,168)==2
        work,_=invoke(wire,complete(work,value=2),PENDING,'write-rest')
        finish(wire,complete(work,4),0,0,3,'retry-and-partial')
    wire,work=start(category='zero-write-start')
    work,_=invoke(wire,complete(work,value=7,token=23),PENDING,'zero-write-open')
    work,_=invoke(wire,complete(work),PENDING,'write-zero')
    finish(wire,complete(work,5),3,0,0,'write-zero-preserved')
    for path in (b'\0',b'a\0b',b'\xff/\0',b'x'*4096+b'\0'):
        wire,work=start(path=path,category='nul-no-effect')
        finish(wire,work,2,0,0,'nul-local')
    for size in (2**21-1,2**21,2**21+1,5*2**20+1):
        wire,work=start(data=b'x'*size,category='chunk-start')
        work,_=invoke(wire,complete(work,value=7,token=23),PENDING,'chunk-open')
        written=0
        while U(work,144)==2:
            count=U(work,168);assert count==min(2**21,size-written)
            written+=count
            work,_=invoke(wire,complete(work,value=count),PENDING,'chunk-complete')
        assert written==size
        finish(wire,complete(work),0,0,size,'chunk-boundaries')
    wire,work=start(category='sequence-wrap-start')
    work=word(word(work,16,MASK),136,MASK)
    work,_=invoke(wire,complete(work,4),PENDING,'sequence-wrap')
    assert U(work,16)==U(work,136)==0
    finish(wire,complete(work,13),1,13,0,'sequence-wrap-no-quota')
    wire,work=start(category='refusal-start')
    for offset,value in ((128,0),(136,7),(144,2),(152,511),(160,1),(168,0x80241),(176,0),
                         (184,2),(192,1),(200,1),(208,1),(216,1),(96,1),(224,1),
                         (8,0),(8,5),(24,5),(32,5),(40,512),(48,1),(56,1),(64,1),
                         (72,1),(80,1),(88,1)):
        invoke(wire,word(work,offset,value),INVALID,'state-or-pending-refusal',unchanged=True)
        counts['state_refusals']+=1
    for error,value,token in ((0,7,0),(0,1<<31,1),(4096,0,0),(4,7,1)):
        bad=complete(work,error,value,token)
        if (error,value,token)==(4,7,1):bad=word(bad,208,1)
        invoke(wire,bad,INVALID,'bad-completion',unchanged=True);counts['completion_refusals']+=1
    for offset in (0,16,24,32,40,48,56):
        invoke(word(wire,offset,U(wire,offset)+1),work,INVALID,'request-refusal',unchanged=True)
        counts['request_refusals']+=1
    for cap in (0,1,7,16,31,47):
        invoke(wire,work,CAPACITY,'output-capacity',outcap=cap,unchanged=True);counts['capacity_refusals']+=1
    for cap in (0,1,8,511,512,513+4+3-1):
        invoke(wire,work[:cap],CAPACITY,'workspace-capacity',unchanged=True);counts['capacity_refusals']+=1
    invoke(word(wire,8,1),work,INVALID,'live-start-refusal',unchanged=True)

def run_state_controls(manifest,out):
    global arrays,rows,counts,began,module
    manifest=Path(manifest);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    arrays=gzip.open(out/'complete-arrays.bin.gz','wb',compresslevel=1)
    rows=gzip.open(out/'entries.jsonl.gz','wb',compresslevel=1)
    counts=collections.Counter();began=time.monotonic()
    build=json.loads(manifest.read_bytes())
    module=NativeModule(manifest,manifest_sha256=sha(manifest.read_bytes()))
    status='FAIL';failure=None
    try:
        controls();status='PASS'
    except BaseException as error:
        failure=repr(error);raise
    finally:
        arrays.close();rows.close();module.close()
        report=dict(schema='hepta.runtime.local-create-state-controls.v1',status=status,error=failure,
                    counts=dict(counts),elapsed_seconds=time.monotonic()-began,source_sha256=build['source_sha256'],
                    image_sha256=build['image_sha256'],actual_kernel_effects=0,
                    typed_completions_only=True,original_rust_execution_performed=False,
                    whole_runtime_replaced=False,public_handler_qualified=False)
        (out/'summary.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    print(json.dumps(run_state_controls(args.manifest.resolve(strict=True),args.output.resolve()),sort_keys=True))
