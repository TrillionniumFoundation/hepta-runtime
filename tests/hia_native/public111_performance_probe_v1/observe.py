"""Observe complete ordinary exchanges before EOF using the retained stdio owner."""
from pathlib import Path
import argparse
import gzip
import json
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_stdio_trace import NativeStdio,file_pin,pin

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('binary','input','output'):p.add_argument('--'+k,type=Path,required=True)
    p.add_argument('--elf-sha256',required=True);p.add_argument('--trace',action='store_true');a=p.parse_args()
    assert a.trace
    binary=a.binary.resolve(strict=True);expected=file_pin(binary);assert expected['sha256']==a.elf_sha256
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    work=out/'workspace';state=out/'state';process=out/'process'
    for q in (work,state,process):q.mkdir(mode=0o700)
    config=out/'runtime.json'
    config.write_text(json.dumps({'state_dir':str(state),'controller_workspace_roots':[str(work)],
        'hosts':{'owned':{'ssh_target':'not-contacted-owned-fixture','remote_state_dir':'/unused'}}})+'\n');config.chmod(0o600)
    raw=a.input.read_bytes();lines=raw.splitlines(keepends=True);assert len(lines)==3 and b''.join(lines)==raw
    owner=None;failure=None;observed=None
    try:
        owner=NativeStdio(binary,expected,work,config,process)
        for seq,(line,frames) in enumerate(zip(lines,(1,0,1),strict=True)):
            row={'opcode':1,'frames':frames,'wire':pin(line),'sequence':seq,'session':0}
            owner.exchange(row,line)
    except BaseException as error:
        failure=error
    finally:
        if owner is not None:
            try:observed=owner.close(failed=failure is not None)
            except BaseException as error:
                if failure is None:failure=error
        if (process/'process.json').is_file():observed=json.loads((process/'process.json').read_bytes())
        if observed is not None:
            for name in ('stdin','stdout','stderr'):
                data=gzip.decompress((process/(name+'.bin.gz')).read_bytes())
                assert pin(data)==observed['streams'][name]['uncompressed']
                (out/(name+'.bin')).write_bytes(data)
            receipt={'schema':'hepta.runtime.task-pump.engineering-process.v2','pid':observed['pid'],
                'command':observed['command'],'cwd':observed['cwd'],'elf':expected,
                'started_ns':observed['started_ns'],'finished_ns':observed['finished_ns'],
                'timeout_seconds':60,'timed_out':observed['timed_out'],'exit_code':observed['returncode'],
                'artifacts':{n:file_pin(out/n) for n in ('stdin.bin','stdout.bin','stderr.bin','process/host-journal.bin','process/host-trace.bin','process/process.json')},
                'observed_process':observed,'whole_public_domain_qualified':False,'fresh_ci_qualified':False,
                'eof_after_complete_exchanges':failure is None,'accepted_input_equals_declared':(out/'stdin.bin').read_bytes()==raw}
            (out/'PROCESS.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
            print(json.dumps(receipt,sort_keys=True),flush=True)
    if failure is not None:raise failure
    assert observed is not None and observed['deadline_seconds']==60 and observed['exchanges']['records']==3
    assert (out/'stdin.bin').read_bytes()==raw and (out/'stdout.bin').read_bytes().count(b'\n')==2

if __name__=='__main__':main()
