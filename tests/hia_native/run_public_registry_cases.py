#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run every fixed event against an actual native or exact original process."""
from pathlib import Path
import argparse,hashlib,json,os,select,subprocess,sys,tempfile,time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from public_registry_cases import cases,compact,configuration
sha=lambda b:hashlib.sha256(b).hexdigest()

def run(binary,case,config,env):
    command=[str(binary),'--runtime-config',str(config)];begun=time.monotonic()
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    pending=bytearray();rows=[]
    try:
        for event in case['events']:
            raw=bytes.fromhex(event['hex']);process.stdin.write(raw+b'\n');process.stdin.flush()
            if not event['response']:continue
            deadline=time.monotonic()+10
            while b'\n'not in pending:
                left=deadline-time.monotonic()
                if left<=0 or not select.select([process.stdout],[],[],left)[0]:raise AssertionError(('response deadline',case['label'],raw))
                part=os.read(process.stdout.fileno(),65536)
                if not part:raise AssertionError(('unexpected EOF',case['label'],raw,process.poll(),process.stderr.read()))
                pending.extend(part)
            out,_,rest=pending.partition(b'\n');pending=bytearray(rest)
            value=json.loads(out)
            # Responses without id are transport InvalidRequest observations,
            # not substitutes for the requested event response.
            request_value=json.loads(raw)
            if 'id'in value:assert value['id']==request_value['id'],(case['label'],value,request_value)
            rows.append({'request_hex':raw.hex(),'response_hex':bytes(out).hex()})
        process.stdin.close();process.wait(timeout=10)
        tail=process.stdout.read();error=process.stderr.read()
        assert not pending and not tail and not error and process.returncode==0,(case['label'],bytes(pending),tail,error,process.returncode)
        request=b''.join(bytes.fromhex(event['hex'])+b'\n'for event in case['events'])
        output=b''.join(bytes.fromhex(row['response_hex'])+b'\n'for row in rows)
        receipt={'label':case['label'],'command':command,'cwd':str(Path.cwd()),'environment':env,
                 'elapsed_seconds':time.monotonic()-begun,'timeout_seconds_per_response':10,
                 'exit_code':process.returncode,'timed_out':False,'input_bytes':len(request),
                 'input_sha256':sha(request),'stdout_bytes':len(output),'stdout_sha256':sha(output),
                 'stderr_bytes':len(error),'stderr_sha256':sha(error),'request_events':len(case['events'])}
        return {'label':case['label'],'rows':rows,'exit_code':process.returncode,'stderr_sha256':sha(error),'stdout_tail_sha256':sha(tail)},receipt
    finally:
        if process.poll()is None:process.kill();process.wait(timeout=3)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--label',choices=['native','original'],required=True);args=parser.parse_args()
    binary=args.binary.resolve(strict=True);data=binary.read_bytes();args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    index=cases();report={'status':'RUNNING','domain':args.label,'binary_sha256':sha(data),'binary_bytes':len(data),'cases_sha256':sha(compact(index)),'planned_sessions':len(index),'completed_sessions':0,'actual_responses':0,'outer_audit_result_lifecycle_closed':False}
    (args.output/'cases.json').write_bytes(compact(index)+b'\n');begun=time.monotonic()
    def save():
        report['elapsed_seconds']=time.monotonic()-begun;(args.output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    save()
    try:
        with tempfile.TemporaryDirectory(prefix='hia-public-registry-',dir=args.output)as td,(args.output/'output.jsonl').open('wb')as output,(args.output/'processes.jsonl').open('wb')as processes:
            root=Path(td);config=root/'config';config.write_bytes(compact(configuration(root/'state')))
            env={'PATH':'','LC_ALL':'C'}
            for case in index:
                row,receipt=run(binary,case,config,env);output.write(compact(row)+b'\n');output.flush();processes.write(compact(receipt)+b'\n');processes.flush();report['completed_sessions']+=1;report['actual_responses']+=len(row['rows']);save()
        assert binary.read_bytes()==data
        out=(args.output/'output.jsonl').read_bytes();proc=(args.output/'processes.jsonl').read_bytes();report.update(status='PASS',output_sha256=sha(out),output_bytes=len(out),processes_sha256=sha(proc),processes_bytes=len(proc))
    except BaseException as error:
        report.update(status='FAIL',error=repr(error));raise
    finally:save();print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
