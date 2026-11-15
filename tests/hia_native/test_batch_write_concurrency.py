"""Actual shared Local batch guards, alias queues, cancellation and parallel files."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import time
import traceback

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from batch_write_supervisor import supervise
from batch_write_trace_common import equal_streams,json_bytes
sha=lambda raw:hashlib.sha256(raw).hexdigest()


def step(content,path=b'target',before=None):
    result={'path_hex':path.hex(),'operations':[{'operation':'insert','start':0,'content':content}]}
    if before is not None:result['before_hex']=before.hex()
    return result


def cases():
    rows=[]
    for aliases in (False,True):
        paths=[b'./target',b'sub/../target',b'././target'] if aliases else [b'target']*3
        rows.append({'name':'four-serialized-'+('dot-aliases' if aliases else 'same-path'),
            'steps':[step('first',before=b'previous\r\n')]+[step('next',path) for path in paths],
            'parallel':{'mode':'serialized','after':0,'end':4,
                        'hold':{'tag':1,'kind':'write','path':'.octofs_tmp_target.tmp'}},
            # The first queued insertion succeeds; the next two must observe
            # the committed line under the same guard and reject duplication.
            'final_files':{'target':b'next\r\nfirst\r\nprevious\r\n'.hex()},
            'comparison':'tag1 exact; tag2..4 identical operations admit a predeclared complete-body multiset; final files exact'})
    rows.append({'name':'cancel-queued-batch-before-guard-release',
        'steps':[step('first',before=b'previous\r\n'),step('canceled',b'./target'),step('next')],
        'parallel':{'mode':'queued-cancel','after':0,'end':3,'cancel_tag':2,
                    'hold':{'tag':1,'kind':'write','path':'.octofs_tmp_target.tmp'}},
        'final_files':{'target':b'next\r\nfirst\r\nprevious\r\n'.hex()},
        'comparison':'complete result by original request tag; final files exact'})
    rows.append({'name':'independent-file-progress-during-held-write',
        'steps':[step('first',before=b'previous\r\n'),step('other',b'other',b'independent\r\n')],
        'parallel':{'mode':'independent','after':0,'end':2,
                    'hold':{'tag':1,'kind':'write','path':'.octofs_tmp_target.tmp'}},
        'final_files':{'target':b'first\r\nprevious\r\n'.hex(),'other':b'other\r\nindependent\r\n'.hex()},
        'comparison':'complete result by original request tag; final files exact'})
    return rows


def response_domain(record,mode):
    rows=sorted(record['frames'],key=lambda row:row['tag'])
    assert [row['tag'] for row in rows]==list(range(1,len(rows)+1))
    def body(row):return struct.pack('<I',row['code'])+bytes.fromhex(row['output_hex'])
    if mode=='serialized':
        # No ordering among simultaneously queued identical edits is promised
        # by the original executor. Preserve tag1, every full body and all tag
        # uniqueness checks; only this declared identical-op group is unordered.
        return struct.pack('<Q',1)+body(rows[0])+b''.join(sorted(body(row) for row in rows[1:]))
    return b''.join(struct.pack('<Q',row['tag'])+body(row) for row in rows)


def run(native,original,destination):
    native=Path(native).resolve(strict=True)
    original=Path(original).resolve(strict=True) if original is not None else None
    destination=Path(destination);destination.mkdir()
    domain=cases();(destination/'cases.json').write_bytes(json_bytes(domain))
    names=('test_batch_write_concurrency.py','batch_write_supervisor.py','batch_write_trace_common.py')
    sources={name:sha((HERE/name).read_bytes()) for name in names}
    result={'schema':'hepta.runtime.batch-write-concurrency.v1','status':'RUNNING','cases':0,'declared_cases':4,
        'native_processes':0,'original_processes':0,'native_requests':0,'original_requests':0,
        'native_sha256':sha(native.read_bytes()),'original_sha256':sha(original.read_bytes()) if original else None,
        'original_status':'PENDING','source_inputs':sources,'observations':[],
        'concurrent_response_order_claimed':False,'public_session_dispatch_qualified':False}
    begun=time.monotonic()
    try:
        for index,config in enumerate(domain):
            entry=destination/(f'{index:02d}-'+config['name']);entry.mkdir()
            fixture=entry/'fixture';fixture.mkdir();(fixture/'sub').mkdir()
            sides=[]
            for label,binary in [('native',native)]+([('original',original)] if original else []):
                if label=='original':shutil.rmtree(fixture);fixture.mkdir();(fixture/'sub').mkdir()
                record=supervise(binary,fixture,config,entry/label)
                assert record['status']=='PASS',(config['name'],label,record['failure'])
                assert record['actual_requests']==len(config['steps'])
                for name,expected in config['final_files'].items():assert (fixture/name).read_bytes()==bytes.fromhex(expected)
                held=[row for row in record['events'] if row.get('control',{}).get('type')=='hold']
                assert len(held)==1
                mode=config['parallel']['mode']
                if mode=='serialized':
                    assert held[0]['release_reason']=='all-other-callers-reached-held-lock'
                    assert held[0]['queued_key_completions']>=3
                    assert sorted(struct.unpack_from('<Q',bytes.fromhex(row['output_hex']),8)[0]
                                  for row in record['frames'])==[0,0,1,1]
                elif mode=='queued-cancel':
                    assert held[0]['release_reason']=='canceled-waiter-removed-before-guard-release'
                    assert held[0]['queued_cancel_sent']==held[0]['queued_cancel_ack']==2
                    assert record['cancel_ack']['effect_still_held'] is True
                    assert record['cancel_ack']['queued_request_completed_before_guard_release'] is True
                else:
                    assert held[0]['release_reason']=='independent-file-complete'
                    assert held[0]['other_request_completed_before_release']==2
                sides.append(record);result[label+'_processes']+=1;result[label+'_requests']+=record['actual_requests']
            assert (entry/'native/stderr.bin').read_bytes()==b''
            response=response_domain(sides[0],config['parallel']['mode'])
            compared={};summary=None
            if original:
                assert response==response_domain(sides[1],config['parallel']['mode']), (config['name'],'complete declared response domain differs')
                assert sides[0]['final_files']==sides[1]['final_files']
                compared['request']=equal_streams(entry/'native/requests.bin',entry/'original/requests.bin')
                compared['files']=equal_streams(entry/'native/filesystem.bin.gz',entry/'original/filesystem.bin.gz',True)
                summary=json.loads((entry/'original/stderr.bin').read_bytes())
                assert summary=={'status':'PASS','original_owner_calls':len(config['steps']),
                                 'responses':len(config['steps']),'canceled':int(config['parallel']['mode']=='queued-cancel')}
            result['observations'].append({'name':config['name'],'comparison':config['comparison'],
                'complete_response_bytes':len(response),'complete_response_sha256':sha(response),
                'compared':compared,'original_summary':summary,
                'native_result_sha256':sha((entry/'native/result.json').read_bytes()),
                'original_result_sha256':sha((entry/'original/result.json').read_bytes()) if original else None})
            result['cases']+=1;(destination/'progress.json').write_bytes(json_bytes(result))
        assert sources=={name:sha((HERE/name).read_bytes()) for name in names}
        assert sha(native.read_bytes())==result['native_sha256']
        if original:
            assert sha(original.read_bytes())==result['original_sha256'];result['original_status']='PASS'
        result['status']='PASS' if original else 'NATIVE_PASS'
    except BaseException as error:result.update(status='FAIL',failure=repr(error),failure_traceback=traceback.format_exc())
    result['elapsed_seconds']=time.monotonic()-begun
    (destination/'result.json').write_bytes(json_bytes(result));return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--original',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=run(args.native,args.original,args.output)
    print(json.dumps({key:value for key,value in result.items() if key!='observations'},sort_keys=True))
    if result['status'] not in ('PASS','NATIVE_PASS'):raise SystemExit(1)
