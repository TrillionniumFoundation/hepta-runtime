"""Actual HIA interleavings with explicitly injected typed completions."""
from pathlib import Path
import ctypes,gzip,hashlib,json,struct,sys,time
Q=lambda n:struct.pack('<Q',n)
U=lambda b,at:struct.unpack_from('<Q',b,at)[0]
MASK=(1<<64)-1


def run(manifest, output, runtime):
    sys.path.insert(0,str(Path(runtime)/'scripts'))
    from hia_native_loader import NativeModule
    output=Path(output);output.mkdir(exist_ok=False)
    module=NativeModule(manifest,manifest_sha256=hashlib.sha256(Path(manifest).read_bytes()).hexdigest())
    arrays=gzip.open(output/'arrays.bin.gz','wb');rows=[];cases=[];began=time.monotonic()

    class Invocation:
        def __init__(self,content=b'abc',path=b'file'):
            self.path=path;self.content=content;self.extent=513+len(path)+len(content)
            self.meta=(self.extent+7)&~7;self.size=self.meta+256+17
            self.work=b'\x5a'*self.size;self.sequence=0;self.last=None
        def word(self,at,value):
            self.work=self.work[:at]+Q(value)+self.work[at+8:]
        def complete(self,*,value=0,error=0,token=0):
            self.work=self.work[:184]+struct.pack('<4Q',1,(-error&MASK)if error else value,error,0 if error else token)+self.work[216:]
        def call(self,op,*,cancel=0,expect=None,generation=1,sequence=None):
            seq=(self.sequence if op in (3,4,5,7)else 0) if sequence is None else sequence
            wire=b'HLCARQ01'+struct.pack('<7Q',op,len(self.path),len(self.content),generation,seq,0,cancel)+self.path+self.content
            initial=(wire,b'\xa7'*160,self.work)
            before=[b'G'*16+raw+b'g'*16 for raw in initial]
            buffers=[ctypes.create_string_buffer(raw,len(raw))for raw in before]
            args=[]
            for raw,buf in zip(initial,buffers):args.extend((ctypes.addressof(buf)+16,len(raw)))
            code=module._entry(*args);after=[buf.raw for buf in buffers]
            assert after[0]==before[0]
            for raw in after:assert raw[:16]==b'G'*16 and raw[-16:]==b'g'*16
            out=after[1][16:-16];state=after[2][16:-16]
            assert out[128:]==initial[1][128:]
            assert state[self.meta+256:]==self.work[self.meta+256:]
            if code in (0xffffffff,0xfffffffe):assert out==initial[1] and state==self.work
            elif code==128:
                assert out[:8]==b'HLCASR01' and U(out,8)==128 and U(out,120)==0
            else:assert code==48 and out[:8]==b'HLCRER01' and out[48:]==initial[1][48:]
            row=dict(number=len(rows)+1,operation=op,code=code,action=U(out,16) if code==128 else None,
                     generation=generation,sequence=seq,cancel=cancel,capacities=[len(x)for x in initial])
            rows.append(row)
            for raw in before+after:arrays.write(Q(len(raw))+raw)
            self.work=state;self.last=out[:code]if code in (48,128)else b''
            if code==128:self.sequence=U(out,40)
            if expect is not None:assert (U(out,16)if code==128 else code)==expect,row
            return self.last
        def syscall(self,*,error=0,partial=None):
            phase=U(self.work,8)
            if phase==1:self.complete(value=0,error=error,token=23)
            elif phase==2:self.complete(value=U(self.work,168)if partial is None else partial,error=error)
            elif phase==3:self.complete(error=error)
            else:raise AssertionError(('not an effect',phase))
            return self.call(4)
        def worker(self):
            out=self.call(4)
            while U(out,16)==8:out=self.syscall()
            assert U(out,16)==9
            return out
        def finish_parent(self,first=2):
            out=self.call(first)
            while len(out)!=48:
                action=U(out,16)
                if action in (1,2):
                    self.call(3,expect=10);self.worker();out=self.call(8)
                elif action==11:out=self.call(7)
                elif action==4:
                    self.complete();out=self.call(5)
                else:raise AssertionError(('unexpected parent action',action))
            return out

    status='FAIL';failure=None
    try:
        for size in (0,1,3,257,2097151,2097152,2097153,4194307):
            inv=Invocation(content=(b'xyz\x00'*((size+3)//4))[:size]);inv.call(1,expect=10)
            result=inv.finish_parent();assert result==b'HLCRER01'+struct.pack('<5Q',48,0,0,size,0)
            inv.call(2,expect=48);cases.append(dict(name='normal',bytes=size))
        for path in (b'\x00',b'a\x00b'):
            inv=Invocation(path=path);inv.call(1);inv.call(2,expect=1);inv.call(3)
            inv.call(8,expect=3);inv.call(4,expect=9);inv.call(2,expect=11)
            result=inv.call(7,expect=48);assert U(result,16)==2
            cases.append(dict(name='nul-in-open-worker',path_hex=path.hex()))
        inv=Invocation();inv.call(1);inv.call(6,expect=6)
        assert inv.work[:512]==bytes(512);inv.call(2,expect=6)
        cases.append(dict(name='unpolled-drop'))
        for size in (0,3,2097153):
            inv=Invocation(content=b'x'*size);inv.call(1);inv.call(2);inv.call(3);inv.call(8,expect=3)
            inv.call(6,expect=6);inv.call(4,expect=8);out=inv.syscall();assert U(out,16)==8 and U(inv.work,8)==3
            inv.complete(error=4);inv.call(4,expect=9);inv.call(7,expect=6)
            assert U(inv.work,inv.meta+96)==0 and U(inv.work,inv.meta+40)==0
            cases.append(dict(name='queued-open-orphan',bytes=size))
        for size in (0,3,2097153):
            inv=Invocation(content=b'x'*size);inv.call(1);inv.call(2);inv.call(3);inv.call(8,expect=3)
            inv.worker();inv.call(6,expect=4)
            assert U(inv.work,8)==3
            inv.complete(error=5);inv.call(5,expect=6);inv.call(7,expect=6)
            assert U(inv.work,inv.meta+96)==0
            cases.append(dict(name='ready-open-inline-drop',bytes=size))
        inv=Invocation(content=b'x'*2097153);inv.call(1);inv.call(2);inv.call(3);inv.worker()
        inv.call(6,expect=10);inv.call(8,expect=11);inv.call(7,expect=2);inv.call(3,expect=10)
        inv.call(8,expect=6);inv.call(4,expect=8)
        inv.syscall(partial=17);assert U(inv.work,56)==17
        inv.syscall(error=4);assert U(inv.work,56)==17
        out=inv.syscall();assert U(out,16)==8 and U(inv.work,8)==3
        assert U(inv.work,56)==2097152 and U(inv.work,64)==2097153
        inv.complete();inv.call(4,expect=9);inv.call(7,expect=6)
        cases.append(dict(name='deferred-poll-cancel-immutable-ticket',completed=2097152))
        inv=Invocation();inv.call(1);inv.call(2);inv.call(3);inv.worker();inv.call(8);inv.call(7,expect=2)
        inv.call(3);inv.worker();inv.call(6,expect=10);inv.call(8,expect=11);inv.call(7,expect=4)
        inv.complete();out=inv.call(5,expect=48);assert U(out,16)==0 and U(out,32)==3
        cases.append(dict(name='ready-poll-wins-deferred-cancel'))
        for mode in ('write-zero','write-error'):
            inv=Invocation();inv.call(1);inv.call(2);inv.call(3);inv.worker();inv.call(8);inv.call(7)
            inv.call(3);inv.call(8,expect=3);inv.call(4,expect=8)
            if mode=='write-zero':inv.complete()
            else:inv.complete(error=28)
            inv.call(4,expect=9);assert U(inv.work,8)==3 and U(inv.work,184)==0
            inv.call(2);inv.call(7,expect=4);inv.complete(error=5);out=inv.call(5,expect=48)
            assert (U(out,16),U(out,24))==((3,0)if mode=='write-zero'else(1,28))
            cases.append(dict(name=mode+'-close-deferred-to-parent'))
        inv=Invocation();inv.call(1);inv.call(2);inv.call(3);inv.call(8)
        inv.call(4,generation=2,expect=0xffffffff);inv.call(4,sequence=inv.sequence+1,expect=0xffffffff)
        inv.worker();inv.call(3,expect=0xffffffff)
        cases.append(dict(name='generation-and-duplicate-admission-refusals'))
        inv=Invocation(content=b'');inv.call(1);inv.call(2);inv.call(3);inv.call(8);inv.worker()
        inv.word(inv.meta+136,1);inv.call(2,expect=0xffffffff)
        inv.word(inv.meta+136,0);inv.call(2,expect=11);inv.call(7,expect=4)
        inv.complete();inv.call(5,expect=48)
        cases.append(dict(name='quiet-close-mode-refusal-is-atomic'))
        bank=[]
        inv=Invocation();inv.call(1);bank.append(('unpolled',inv.path,inv.content,inv.work))
        inv.call(2);bank.append(('prepared-open',inv.path,inv.content,inv.work))
        inv.call(3);bank.append(('queued-open',inv.path,inv.content,inv.work))
        inv.call(8);inv.call(4);bank.append(('running-open',inv.path,inv.content,inv.work))
        inv.syscall();bank.append(('ready-open',inv.path,inv.content,inv.work))
        inv.call(2);inv.call(7);bank.append(('prepared-write',inv.path,inv.content,inv.work))
        inv.call(3);inv.call(8);inv.call(4);bank.append(('running-write',inv.path,inv.content,inv.work))
        inv.syscall();bank.append(('ready-write',inv.path,inv.content,inv.work))
        inv.call(2);inv.call(7);bank.append(('inline-close',inv.path,inv.content,inv.work))
        inv.complete();inv.call(5);bank.append(('done',inv.path,inv.content,inv.work))
        matrix_calls=0;matrix_refusals=0
        for label,path,data,state in bank:
            for offset in range(16,192,8):
                for value in (0,1,2,3,4,5,6,7,8,MASK):
                    for operation in range(1,9):
                        probe=Invocation(data,path);probe.work=state
                        probe.word(probe.meta+offset,value);probe.sequence=U(probe.work,probe.meta+48)
                        result=probe.call(operation)
                        matrix_calls+=1
                        if not result:matrix_refusals+=1
        cases.append(dict(name='metadata-command-refusal-atomicity-matrix',contexts=len(bank),calls=matrix_calls,refusals=matrix_refusals))
        status='PASS'
    except BaseException as error:
        failure=repr(error);raise
    finally:
        arrays.close();module.close()
        (output/'rows.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
        report=dict(schema='hepta.runtime.create-async-segment-probe.v1',status=status,error=failure,
                    cases=cases,calls=len(rows),elapsed_seconds=time.monotonic()-began,
                    manifest=str(manifest),manifest_sha256=hashlib.sha256(Path(manifest).read_bytes()).hexdigest(),
                    actual_kernel_effects=0,typed_completions_only=True,async_original_comparison_performed=False,
                    public_handler_qualified=False,whole_runtime_replaced=False)
        (output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(run(args.manifest.resolve(strict=True),args.output.resolve(),Path(__file__).resolve().parents[3]),sort_keys=True))
