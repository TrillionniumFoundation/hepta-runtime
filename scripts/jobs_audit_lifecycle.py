#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual audit-image lifecycle, ownership and failure boundaries."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import threading
import time
from jobs_audit_driver import Audit


def need(condition,message):
    if not condition:raise AssertionError(message)


def fd_count():return len(os.listdir('/proc/self/fd'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--manifests',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    signal.alarm(60)
    cases=[]
    def record(name,details):
        cases.append({'name':name,'passed':True,'details':details})
        (out/'CASES.json').write_text(json.dumps(cases,sort_keys=True,indent=2)+'\n')
    start_fds=fd_count()
    audit=Audit(args.library,args.manifests)
    try:
        context=audit.context;lib=audit.lib
        entries=[module._address for module in audit.modules]
        for index in range(5):
            bad=entries[:];bad[index]=0
            need(lib.jobs_audit_create(*bad,0)==-22,'null fixed child was admitted')
        need(lib.jobs_audit_create(*entries,2)==-22,'invalid AT_SECURE admitted')
        need(lib.jobs_audit_output(0) is None,'null output context admitted')
        need(lib.jobs_audit_destroy(0)==-22 and lib.jobs_audit_release(0)==-22,'null lifecycle context admitted')
        record('create-and-null-admission',{'null_children':5,'invalid_secure':1,'null_lifecycle':3})
        request=Audit.request(str(out/'leased-state'),'host','subject')
        source=ctypes.create_string_buffer(request)
        code=lib.jobs_audit_invoke(context,source,len(request))
        need(code==32,'initial lease did not complete')
        pointer=lib.jobs_audit_output(context);before=ctypes.string_at(pointer,code)
        need(lib.jobs_audit_invoke(context,source,len(request))==0xfffffffc,'same-thread live lease was replaced')
        need(lib.jobs_audit_destroy(context)==-16,'live lease was destroyed')
        need(lib.jobs_audit_output(context)==pointer and ctypes.string_at(pointer,code)==before,'borrowed bytes changed')
        need(lib.jobs_audit_release(context)==0,'first release failed')
        need(lib.jobs_audit_output(context) is None and lib.jobs_audit_release(context)==-22,'released result remained live')
        again=audit.invoke(request);need(again['code']==32,'context did not recover after release')
        record('borrow-reentrance-and-destruction',{'response_sha256':hashlib.sha256(before).hexdigest(),'next':again})
        baseline=fd_count()-audit.diagnostic()['live_handles']
        need(baseline==start_fds,'canonical private descriptors escaped the registry')
        record('actual-descriptor-ownership',audit.diagnostic())

        # A held response keeps every competing native call waiting. CDLL
        # releases the Python GIL; serialization is the boundary's real futex.
        code=lib.jobs_audit_invoke(context,source,len(request));need(code==32,'concurrent seed failed')
        results=[];errors=[];entered=[threading.Event() for _ in range(8)]
        def worker(index):
            entered[index].set()
            try:
                value=audit.invoke(Audit.request(str(out/'leased-state'),'thread-'+str(index),'subject'))
                results.append(value)
            except BaseException as error:errors.append(repr(error))
        threads=[threading.Thread(target=worker,args=(i,),daemon=True) for i in range(8)]
        for thread in threads:thread.start()
        for event in entered:need(event.wait(2),'native caller did not start')
        time.sleep(0.03)
        need(not results and not errors,'competing invocation replaced a held response')
        need(lib.jobs_audit_destroy(context)==-16,'concurrent borrowed owner destroyed')
        need(lib.jobs_audit_release(context)==0,'concurrent seed release failed')
        for thread in threads:thread.join(10)
        need(all(not thread.is_alive() for thread in threads),'futex caller did not resume')
        need(not errors and len(results)==8 and all(row['code']==32 for row in results),'concurrent audit result differs')
        sequences=[row['state']['sequence'] for row in results]
        need(len(set(sequences))==8,'shared effect chain was reused')
        rows=(out/'leased-state/audit/events.jsonl').read_bytes().splitlines()
        need(len(rows)==11,'concurrent events missing or duplicated')
        hosts=[json.loads(row)['host'] for row in rows]
        need(all(hosts.count('thread-'+str(i))==1 for i in range(8)),'concurrent event payload changed')
        record('eight-real-concurrent-callers',{'sequences':sequences,'events':len(rows),'errors':errors})

        # A fork cannot inherit ownership of this process-local descriptor set.
        before_state=audit.diagnostic();pid=os.fork()
        if pid==0:
            try:
                valid=(lib.jobs_audit_invoke(context,source,len(request))==0xffffffff
                       and lib.jobs_audit_destroy(context)==-22
                       and lib.jobs_audit_output(context) is None)
                os._exit(0 if valid else 71)
            except BaseException:os._exit(72)
        _,status=os.waitpid(pid,0)
        need(os.waitstatus_to_exitcode(status)==0,'fork imported the old process owner')
        need(audit.diagnostic()==before_state,'fork changed the parent audit owner')
        record('fork-owner-refusal',{'child_exit':os.waitstatus_to_exitcode(status)})

        # Workspace movement must retain every HIA namespace/descriptor proof.
        large='x'*(2<<20)
        grown=audit.invoke(Audit.request(str(out/'leased-state'),large,'large-event'))
        need(grown['code']==32 and grown['state']['workspace_capacity']>2<<20,'checked native growth failed')
        lines=(out/'leased-state/audit/events.jsonl').read_bytes().splitlines()
        need(json.loads(lines[-1])['host']==large,'growth changed original event bytes')
        restored=audit.invoke(request);need(restored['code']==32,'grown context did not resume')
        record('growth-retains-owner-and-input',{'host_bytes':len(large),'grown':grown,'resumed':restored})

        # A true HIA request refusal must close the complete context registry;
        # no subsequent valid request may turn the poisoned owner into success.
        refused=audit.invoke(b'invalid')
        need(refused['code']==0xffffffff and refused['state']['poison']==1,'actual HIA refusal not retained')
        need(refused['state']['ready']==0 and refused['state']['live_handles']==0,'native refusal retained publication proof')
        need(fd_count()==baseline,'native refusal leaked descriptors')
        replay=audit.invoke(request)
        need(replay['code']==0xfffffffc and replay['frame_hex']=='','poisoned context granted a write')
        record('refusal-retires-all-descriptors',{'refused':refused,'subsequent':replay})
    finally:audit.close()
    need(fd_count()==start_fds,'destroy leaked an actual process descriptor')
    record('final-destruction',{'before_fds':start_fds,'after_fds':fd_count()})
    result={'schema':'hepta.runtime.jobs-audit.lifecycle.v1','passed':True,
            'production_boundary':str(args.library.resolve()),'manifest_list':str(args.manifests.resolve()),
            'test_probe_carrier':False,'cases':cases,'public_route_qualified':False}
    (out/'EVIDENCE.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'passed':True,'cases':len(cases),'evidence':str(out/'EVIDENCE.json')}))


if __name__=='__main__':main()
