"""Execute the complete fixed held-boundary corpus against one actual binary."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from held_cases import run

CORPUS_SHA='069ba8299eff7b39583ef8f1be54ff855a7c038f2b5f817f0039659cf77a906e'
FILES=('cases.json','owned_trace.py','held_cases.py','run_held.py')


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def compact(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def sources(root=HERE):
    root=Path(root)
    return {name:pin((root/name).read_bytes())for name in FILES}


def cases(root=HERE):
    raw=(Path(root)/'cases.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==CORPUS_SHA
    result=json.loads(raw)
    assert result['case_count']==len(result['cases'])==43
    assert len({row['name']for row in result['cases']})==43
    assert result['process_deadline_seconds']==60 and result['qualifier_deadline_seconds']==180
    return result


def execute(binary,output,mode):
    started=time.monotonic();output=Path(output).resolve();output.mkdir(exist_ok=False)
    binary=Path(binary).resolve(strict=True);corpus=cases();before=sources()
    identity=pin(binary.read_bytes());rows=[]
    report=dict(schema='hepta.runtime.local-create-held-execution.v1',status='RUNNING',mode=mode,
        execution=dict(output=str(output),source=str(HERE),binary=str(binary)),
        binary_before=identity,binary_after=None,source_before=before,source_after=None,
        corpus_sha256=CORPUS_SHA,case_count=43,process_deadline_seconds=60,
        qualifier_deadline_seconds=180,scope=corpus['scope'],rows=rows,
        retired_fixture_directories=0)
    def save():(output/'summary.json').write_bytes(compact(report)+b'\n')
    save()
    try:
        for index,spec in enumerate(corpus['cases']):
            if time.monotonic()-started>=180:raise TimeoutError('unchanged 180-second complete held-corpus deadline')
            result=run(binary,output/spec['name'],mode,spec['scenario'],spec['size'],**spec['options'])
            assert result['syscall_counts']==spec['expected_calls']
            assert result['policy']['expected_file_bytes']==spec['expected_file_bytes']
            actual=dict(result['policy']['semantic_result']);actual.pop('written',None)
            assert actual==spec['expected_result']
            trace=output/spec['name']/'trace'
            row=dict(index=index,name=spec['name'],result_sha256=pin((trace/'result.json').read_bytes())['sha256'],
                     syscall_counts=result['syscall_counts'],file=result['file'],
                     owned_processes=len(result['owned_pids']),elapsed_seconds=result['elapsed_seconds'])
            rows.append(row);save()
            print(compact(dict(case=index+1,name=spec['name'],mode=mode,status='PASS')).decode(),flush=True)
        assert sources()==before and pin(binary.read_bytes())==identity
        for spec in corpus['cases']:
            work=output/spec['name']/'work'
            entries=list(work.iterdir())
            expected=[] if spec['expected_file_bytes']is None else ['created.bin']
            assert sorted(p.name for p in entries)==expected
            for path in entries:
                assert path.is_file()and not path.is_symlink();path.unlink()
            work.rmdir();report['retired_fixture_directories']+=1
        report.update(status='PASS',source_after=sources(),binary_after=pin(binary.read_bytes()),
                      elapsed_seconds=time.monotonic()-started,
                      actual_root_processes=len(rows),
                      actual_owned_processes=sum(row['owned_processes']for row in rows))
        assert report['elapsed_seconds']<=180
    except BaseException as error:
        report.update(status='FAIL',error=dict(type=type(error).__name__,message=str(error)),
                      elapsed_seconds=time.monotonic()-started)
        raise
    finally:save()
    print(compact(report).decode(),flush=True)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True)
    parser.add_argument('--output',required=True);parser.add_argument('--mode',choices=('rust','native'),required=True)
    args=parser.parse_args();execute(args.binary,args.output,args.mode)
