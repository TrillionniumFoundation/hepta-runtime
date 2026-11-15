"""Actual isolated process admission fences for the new private async wire."""
from pathlib import Path
import argparse,hashlib,json,os,struct,subprocess,sys,time,traceback

MASK=(1<<64)-1
Q=lambda n:struct.pack('<Q',n)
U=lambda b,n:struct.unpack_from('<Q',b,n)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
pin=lambda b:dict(bytes=len(b),sha256=sha(b))


def cases():
    valid=b'HLCARQ01'+struct.pack('<7Q',1,7,3,1,0,0,0)+b'createdabc'
    result=[('truncated-'+str(size),valid[:size],False)for size in range(64)]
    def replace(name,offset,value):
        raw=bytearray(valid);struct.pack_into('<Q',raw,offset,value);result.append((name,bytes(raw),False))
    for command in (0,2,3,4,5,6,7,8,9,MASK):replace('private-command-'+str(command),8,command)
    for offset,values in ((32,(0,)),(40,(1,MASK)),(48,(1,MASK)),(56,(1,2,MASK)),
                          (16,(8,MASK)),(24,(0,2,4,MASK))):
        for value in values:replace('header-'+str(offset)+'-'+str(value),offset,value)
    result.extend((('short-body',valid[:-1],False),('long-body',valid+b'x',False)))
    for index in range(8):
        raw=bytearray(valid);raw[index]^=1;result.append(('wrong-magic-'+str(index),bytes(raw),False))
    for generation in (1,2,MASK):
        raw=bytearray(valid);struct.pack_into('<Q',raw,32,generation)
        result.append(('accepted-generation-'+str(generation),bytes(raw),True))
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    binary=args.binary.resolve(strict=True);output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[3]
    sys.path.insert(0,str(root/'scripts'))
    from hia_native_local_create_build import source_evidence
    component=source_evidence(root)
    assert sha(binary.read_bytes())==component['executable_sha256']
    report=dict(schema='hepta.runtime.local-create-async-admission-controls.v1',status='RUNNING',source_root=str(root),output=str(output),component=component,
        executable=dict(path=str(binary),**pin(binary.read_bytes())),cases=[],
        async_cancellation_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    began=time.monotonic()
    try:
        for index,(name,frame,accepted)in enumerate(cases()):
            folder=output/str(index);folder.mkdir();work=folder/'files';work.mkdir()
            stdin=Q(len(frame))+frame;(folder/'stdin.bin').write_bytes(stdin)
            started=time.monotonic()
            process=subprocess.run([str(binary)],input=stdin,cwd=work,env={'PATH':'','LC_ALL':'C'},
                capture_output=True,timeout=60,umask=0o022)
            (folder/'stdout.bin').write_bytes(process.stdout);(folder/'stderr.bin').write_bytes(process.stderr)
            row=dict(name=name,accepted=accepted,command=[str(binary)],cwd=str(work),environment={'PATH':'','LC_ALL':'C'},
                umask=0o022,timeout_seconds=60,elapsed_seconds=time.monotonic()-started,exit_code=process.returncode,
                stdin=pin(stdin),stdout=pin(process.stdout),stderr=pin(process.stderr))
            (folder/'execution.json').write_text(json.dumps(row,sort_keys=True)+'\n')
            assert process.returncode==0,(name,process.returncode)
            if accepted:
                assert process.stdout==Q(48)+b'HLCRER01'+struct.pack('<5Q',48,0,0,3,0)
                assert os.listdir(work)==['created']and(work/'created').read_bytes()==b'abc'
                (folder/'created.bin').write_bytes((work/'created').read_bytes())
                offset=0;journals=[];effects=[]
                while offset<len(process.stderr):
                    magic=process.stderr[offset:offset+8]
                    size=128 if magic==b'HLCASR01'else 96
                    raw=process.stderr[offset:offset+size];assert len(raw)==size
                    if magic==b'HLCASR01':
                        assert U(raw,8)==128 and U(raw,32)==U(frame,32) and U(raw,120)==0
                        journals.append(raw)
                    else:
                        assert magic==b'HLCREF01'and U(raw,8)==len(effects)+1 and U(raw,88)==0
                        effects.append(raw)
                    offset+=size
                assert offset==len(process.stderr)and journals and [U(x,16)for x in effects]==[1,2,3]
                row.update(actual_effect_records=len(effects),complete_journal_records=len(journals))
            else:
                assert process.stdout==Q(0xffffffff)and process.stderr==b'',name
                assert os.listdir(work)==[],name
                row.update(actual_effect_records=0,complete_journal_records=0)
            (folder/'result.json').write_text(json.dumps(row,sort_keys=True)+'\n');report['cases'].append(row)
        assert sha(binary.read_bytes())==component['executable_sha256'] and source_evidence(root)==component
        report.update(status='CAPTURED',elapsed_seconds=time.monotonic()-began,
            actual_processes=len(report['cases']),refusals=sum(not row['accepted']for row in report['cases']),
            accepted_generations=3,timeout_seconds_per_process=60,driver=pin(Path(__file__).read_bytes()))
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),elapsed_seconds=time.monotonic()-began)
        traceback.print_exc();raise
    finally:
        (output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        summary={k:v for k,v in report.items()if k not in('cases','component')}
        summary['result_sha256']=sha((output/'result.json').read_bytes())
        (output/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
        print(json.dumps(summary,sort_keys=True),flush=True)


if __name__=='__main__':main()
