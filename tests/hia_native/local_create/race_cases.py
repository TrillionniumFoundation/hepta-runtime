"""Two live independent processes race the same post-preflight create pathname."""
from pathlib import Path
import argparse,concurrent.futures,gzip,hashlib,json,os,struct,subprocess,threading,time

def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(data):return b'HLCREQ01'+struct.pack('<7Q',1,7,len(data),0,0,0,0)+b'created'+data

def run_races(binary,output,original):
    output.mkdir(parents=True,exist_ok=False);started=time.monotonic();records=[]
    status='FAIL';error=None
    try:
        for number in range(32):
            folder=output/str(number);folder.mkdir();work=folder/'files';work.mkdir()
            payloads=[b'first caller bytes',b'second caller bytes']
            inputs=[wire(value) for value in payloads]
            if not original:inputs=[struct.pack('<Q',len(value))+value for value in inputs]
            processes=[subprocess.Popen([str(binary)],cwd=work,env={'PATH':'','LC_ALL':'C'},
                       stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,umask=0o022) for unused in range(2)]
            assert all(process.poll() is None for process in processes)
            assert len({process.pid for process in processes})==2
            barrier=threading.Barrier(3)
            def send(index):
                barrier.wait(timeout=30);begin=time.monotonic()
                stdout,stderr=processes[index].communicate(inputs[index],timeout=60)
                return dict(index=index,pid=processes[index].pid,exit_code=processes[index].returncode,
                            elapsed_seconds=time.monotonic()-begin,stdout=stdout,stderr=stderr)
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
                    futures=[workers.submit(send,index) for index in range(2)]
                    barrier.wait(timeout=30);answers=[future.result(timeout=65) for future in futures]
            finally:
                for process in processes:
                    if process.poll() is None:process.kill()
                    process.wait(timeout=10)
            parsed=[]
            for answer in answers:
                index=answer['index'];assert answer['exit_code']==0
                with gzip.open(folder/(str(index)+'.stdin.bin.gz'),'wb') as stream:stream.write(inputs[index])
                (folder/(str(index)+'.stdout.bin')).write_bytes(answer['stdout'])
                (folder/(str(index)+'.stderr.bin')).write_bytes(answer['stderr'])
                body=answer.pop('stdout');stderr=answer.pop('stderr')
                answer['stdout']=dict(bytes=len(body),sha256=sha(body));answer['stderr']=dict(bytes=len(stderr),sha256=sha(stderr))
                if not original:
                    assert len(body)==56 and struct.unpack_from('<Q',body)[0]==48
                    body=body[8:];assert len(stderr)%96==0
                    effects=[struct.unpack_from('<12Q',stderr,at) for at in range(0,len(stderr),96)]
                    assert effects[0][2:7]==(1,512,7,0x800c1,438)
                else:assert stderr==b'HLCREATE-REFERENCE-BEGIN\nHLCREATE-REFERENCE-END\n'
                assert body[:8]==b'HLCRER01' and len(body)==48
                extent,kind,errno,written,reserved=struct.unpack_from('<5Q',body,8)
                assert extent==48 and reserved==0
                assert (kind,errno) in ((0,0),(1,17))
                if kind==0:assert written==len(payloads[index])
                parsed.append((kind,errno))
            assert sorted(parsed)==[(0,0),(1,17)]
            winner=parsed.index((0,0));raw=(work/'created').read_bytes()
            assert raw==payloads[winner]
            (folder/'created.bin').write_bytes(raw)
            row=dict(number=number,winner=winner,processes=answers,results=parsed,
                     final_file=dict(bytes=len(raw),sha256=sha(raw)),
                     both_processes_live_before_input_release=True)
            (folder/'result.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n');records.append(row)
        status='PASS'
    except BaseException as caught:error=repr(caught);raise
    finally:
        report=dict(schema='hepta.runtime.local-create-races.v1',status=status,error=error,
                    pairs=len(records),actual_processes=2*len(records),original_rust=original,
                    executable=str(binary),executable_sha256=sha(binary.read_bytes()),
                    elapsed_seconds=time.monotonic()-started,timeout_seconds_per_process=60,
                    native_public_handler_qualified=False,whole_runtime_replaced=False)
        (output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps(report,sort_keys=True),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--original',action='store_true')
    args=parser.parse_args();run_races(args.binary.resolve(strict=True),args.output.resolve(),args.original)
