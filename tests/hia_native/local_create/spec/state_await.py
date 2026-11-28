"""Actual HIA mkdir await transitions with explicitly typed completions."""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,json,struct,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
Q=lambda n:struct.pack('<Q',n)
U=lambda b,n:struct.unpack_from('<Q',b,n)[0]
MASK=(1<<64)-1


def main(manifest,output):
    output.mkdir(parents=True,exist_ok=False)
    module=NativeModule(manifest,manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
    arrays=gzip.open(output/'arrays.bin.gz','wb');rows=[];cases=[];began=time.monotonic()
    report=dict(schema='hepta.runtime.local-create-spec-await-capture.v1',status='RUNNING',actual_kernel_operations=False,typed_completions_only=True,manifest=str(manifest),manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())

    class Invocation:
        def __init__(self):self.work=bytes(512)+b'TAIL'*7
        def word(self,at,value):self.work=self.work[:at]+Q(value)+self.work[at+8:]
        def complete(self,kind=0,error=0,cache=1):
            self.word(248,1)
            self.work=self.work[:256]+b'HSHMKR01'+struct.pack('<3Q',kind,error,cache)+self.work[288:]
        def call(self,op,cancel=0,expect=None,generation=1,seq=None,ocap=160,wcap=None):
            sequence=(0 if op in(1,2,6,8)else 1)if seq is None else seq
            wire=b'HLCMAQ01'+struct.pack('<7Q',op,0,0,generation,sequence,0,cancel)
            state=self.work if wcap is None else self.work[:wcap]
            before=[b'G'*16+raw+b'g'*16 for raw in(wire,b'\xa7'*ocap,state)]
            buffers=[ctypes.create_string_buffer(raw,len(raw))for raw in before];args=[]
            for raw,buf in zip(before,buffers):args.extend((ctypes.addressof(buf)+16,len(raw)-32))
            code=module._entry(*args);after=[b.raw for b in buffers]
            for raw in after:assert raw[:16]==b'G'*16 and raw[-16:]==b'g'*16
            assert after[0]==before[0]
            body=after[1][16:-16];work=after[2][16:-16]
            if code in(0xffffffff,0xfffffffe):assert before[1:]==after[1:]
            elif code==128:
                assert body[:8]==b'HLCASR01'and U(body,8)==128 and U(body,32)==generation and U(body,120)==0
                assert body[128:]==before[1][144:-16]
            else:assert code==32 and body[:8]==b'HSHMKR01'and body[32:]==before[1][48:-16]
            assert work[512:]==state[512:]
            row=dict(number=len(rows)+1,operation=op,cancel=cancel,code=code,
                action=U(body,16)if code==128 else None,capacities=[len(x)-32 for x in before])
            rows.append(row)
            for raw in before+after:arrays.write(Q(len(raw))+raw)
            if wcap is None:self.work=work
            observed=U(body,16)if code==128 else code
            if expect is not None:assert observed==expect,row
            return code,body[:code]if code in(32,128)else b''

    try:
        bank=[]
        for kind,error in((0,0),(1,13),(1,4),(1,17),(1,4095),(2,0)):
            for cache in(0,1,2):
                for early in(False,True):
                    inv=Invocation();inv.call(1,expect=10);inv.call(2,expect=12);inv.call(3,expect=10)
                    if not early:
                        inv.call(8,expect=3)
                        for _ in range(3):inv.call(2,expect=3)
                    inv.call(4,expect=8);inv.complete(kind,error,cache);inv.call(5,expect=9)
                    inv.call(8 if early else 2,expect=11);inv.call(7,expect=10)
                    code,body=inv.call(8,cancel=1,expect=32)
                    assert body==b'HSHMKR01'+struct.pack('<3Q',kind,error,cache)
                    inv.call(2,expect=0xffffffff)
                    cases.append(dict(name='completion',kind=kind,errno=error,cache=cache,ready_before_wait=early))
        for point in('unpolled','queued','running','ready'):
            inv=Invocation();inv.call(1,expect=10)
            if point=='unpolled':inv.call(2,cancel=1,expect=6)
            else:
                inv.call(2,expect=12);inv.call(3,expect=10);inv.call(8,expect=3)
                if point!='queued':inv.call(4,expect=8)
                if point=='ready':inv.complete();inv.call(5,expect=9)
                inv.call(2,cancel=1,expect=6)
                if point=='queued':inv.call(4,expect=8)
                if point!='ready':inv.complete();inv.call(5,expect=9)
                inv.call(7,cancel=1,expect=6)
            cases.append(dict(name='cancel-'+point))
        inv=Invocation();inv.call(1);bank.append(('unpolled',inv.work))
        inv.call(2);bank.append(('prepared',inv.work));inv.call(3);bank.append(('queued-polling',inv.work))
        inv.call(8);bank.append(('queued-waiting',inv.work));inv.call(4);bank.append(('running',inv.work))
        inv.complete();bank.append(('completion-before-publication',inv.work));inv.call(5);bank.append(('ready',inv.work))
        inv.call(2);bank.append(('ready-polling',inv.work));inv.call(7);bank.append(('reaped',inv.work))
        inv.call(8);bank.append(('done',inv.work))
        inv=Invocation();inv.call(1);inv.call(2);inv.call(3);inv.call(8);inv.call(2,cancel=1);bank.append(('cancel-queued',inv.work))
        inv.call(4);bank.append(('cancel-running',inv.work));inv.complete();inv.call(5);bank.append(('cancel-ready',inv.work))
        inv.call(7);bank.append(('cancel-drained',inv.work))
        for label,state in bank:
            for offset in(8,16,24,32,40,48,56,64,128,240,248,256,264,272,280,288,504):
                for value in(0,1,2,3,4,5,6,7,MASK):
                    for operation in range(1,9):
                        inv=Invocation();inv.work=state;inv.word(offset,value);inv.call(operation)
        cases.append(dict(name='state-command-matrix',states=len(bank),fields=17,values=9,operations=8))
        for label,state in bank:
            inv=Invocation();inv.work=state;inv.call(2,generation=2,expect=0xffffffff)
            inv.call(2,seq=1,expect=0xffffffff)
            inv.call(2,ocap=127,expect=0xfffffffe)
            inv.call(2,wcap=511,expect=0xfffffffe)
        report.update(status='PASS',calls=len(rows),cases=cases,elapsed_seconds=time.monotonic()-began)
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),calls=len(rows),cases=cases,elapsed_seconds=time.monotonic()-began)
        traceback.print_exc();raise
    finally:
        arrays.close();module.close()
        (output/'rows.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
        (output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps(report,sort_keys=True),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();main(args.manifest.resolve(),args.output.resolve())
