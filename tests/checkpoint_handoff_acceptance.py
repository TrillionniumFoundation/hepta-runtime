#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Resume an application checkpoint actually produced by a DC-started fixture.
No PID adoption, process-memory copying, or mutation of unrelated DC sessions.
All resumed operations use the native local MCP CLI, never a DC process API.
"""
import argparse
import fcntl
import hashlib
import json
import pathlib
import subprocess
import sys
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--directory',required=True);ap.add_argument('--dc-output',required=True);ap.add_argument('--dc-exit',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    root=pathlib.Path(a.directory).resolve(strict=True)
    source=json.loads((root/'checkpoint-dc.json').read_text());journal=root/'effects.jsonl'
    assert pathlib.Path(a.dc_exit).read_text().strip()=='0'
    output=[json.loads(line) for line in pathlib.Path(a.dc_output).read_text().splitlines()]
    assert output[-1]==source and source['phase']=='dc' and source['total']==5 and source['effects']==2
    before=journal.read_bytes();assert hashlib.sha256(before).hexdigest()==source['journal_sha256']
    with (root/'owner.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    def call(name,args):
        p=subprocess.run([sys.executable,str(ROOT/'deploy/operator-call.py')],input=json.dumps({'name':name,'arguments':args}),capture_output=True,text=True,timeout=110)
        if p.returncode:raise RuntimeError(p.stderr or p.stdout)
        result=json.loads(p.stdout)
        if result.get('isError'):raise RuntimeError(str(result))
        text=next(block['text'] for block in result['content'] if block['type']=='text')
        return json.loads(text)
    started=call('pty_start',{'host':'main','executable':'/usr/bin/python3','args':['-u',str(ROOT/'tests/checkpoint_handoff_fixture.py'),'--directory',str(root),'--phase','runtime'],'idempotency_key':root.name+'-resume'})
    sid=started['session_id']
    try:
        for _ in range(80):
            page=call('pty_read',{'host':'main','session_id':sid})
            if '"event": "READY"' in page['text']:break
            time.sleep(.05)
        else:raise AssertionError('native resumed application not ready')
        ready=next(json.loads(line) for line in page['text'].splitlines() if line.startswith('{') and 'READY' in line)
        assert ready['total']==5 and ready['effects']==2 and ready['phase']=='runtime' and ready['pid']!=source['pid']
        text='\n'.join(json.dumps(x) for x in [{'id':'dc-2','add':3},{'id':'runtime-1','add':7},{'checkpoint':True}])+'\n'
        sent=call('pty_write',{'host':'main','session_id':sid,'data':text,'request_id':'handoff-resume-batch'})
        assert sent.get('complete'),sent
        for _ in range(80):
            page=call('pty_read',{'host':'main','session_id':sid})
            if page['status']['state']!='running':break
            time.sleep(.05)
        assert page['output_complete'] and page['status']['exit_code']==0,page
        result=json.loads((root/'checkpoint-runtime.json').read_text())
        assert result['total']==12 and result['effects']==3
        after=journal.read_bytes();assert after.startswith(before) and hashlib.sha256(after).hexdigest()==result['journal_sha256']
        entries=[json.loads(line) for line in after.decode().splitlines()]
        assert [e['id'] for e in entries]==['dc-1','dc-2','runtime-1']
        assert '"reused": true' in page['text']
        report={'complete':True,'scope':'application-supported checkpoint/drain/resume, not transparent live-pipe migration',
                'dc_started_process_pid':source['pid'],'dc_exit_code':0,'dc_snapshot':source,
                'native_runtime_session_id':sid,'native_process_pid':ready['pid'],'native_snapshot':result,
                'original_journal_prefix_preserved':True,'no_duplicated_effect':True,'native_terminal_output_complete':True,
                'native_calls_used':'deploy/operator-call.py -> authenticated loopback MCP',
                'unrelated_dc_sessions_modified':False,'application_checkpoint_support_required':True,
                'transparent_pid_or_pipe_migration_claimed':False,'cloud_binding_used':False}
        pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
        print('CHECKPOINT_HANDOFF_PASS '+json.dumps({'before':5,'after':12,'unique_effects':3,'native_session':sid}))
    finally:call('pty_close',{'host':'main','session_id':sid})


if __name__=='__main__':main()
