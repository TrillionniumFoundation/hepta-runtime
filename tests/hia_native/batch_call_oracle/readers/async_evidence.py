"""Pure reader for two real Linux cancellation/late-worker lock controls."""
from pathlib import Path
import gzip,struct
from capture_format import Files,actual_process,canonical,fields,need,same,sha,strict_json,uint
import native_predecessor as native

def control_evidence(files,run,process_run,script,native_run,native_source,manifest):
    run,process_run,script=map(Path,(run,process_run,script))
    native_run,native_source,manifest=map(Path,(native_run,native_source,manifest))
    artifacts={}
    def raw(path):
        path=str(path);value=files.raw(path);artifacts[path]=sha(value);return value
    def js(path):return strict_json(raw(path))
    def pin(path):
        value=raw(path);return {'bytes':len(value),'sha256':sha(value)}
    def data(value):
        fields(value,('artifact','bytes','sha256'),'complete cancel control blob')
        need(value['artifact']=='blobs/'+value['sha256']+'.bin.gz','control content address')
        value_raw=gzip.decompress(raw(run/value['artifact']))
        same({'bytes':len(value_raw),'sha256':sha(value_raw)},{k:value[k]for k in('bytes','sha256')},
             'complete cancellation control blob')
        return value_raw
    meta=js(manifest);elf=manifest.parent/meta['elf']
    same(pin(elf)['sha256'],meta['elf_sha256'],'actual control frozen ELF')
    source=js(run/'SOURCE.json')
    rows=js(run/'CONTROLS.json')
    same([r['case_id']for r in rows],[213,214],'two separate source-owned cancel controls')
    native_rows={r['case_id']:r for r in native.json_lines(raw(native_run/'output-async/native-cases.jsonl'))}
    expected_sources=[script,manifest,elf,native_source/'tests/hia_native/batch_call_capture.py',
        native_source/'tests/hia_native/batch_call_oracle/cases.py',native_run/'output-async/native-cases.jsonl']
    expected_sources += [native_run/'output-async'/native_rows[n]['typed']['artifact']for n in(213,214)]
    same(sorted(source),sorted(map(str,expected_sources)),'complete cancellation control selected source closure')
    for path,expected in source.items():same(pin(path),expected,'actual control source/input identity')
    proc=js(process_run/'PROCESS.json')
    fields(proc,('command','cwd','pid','started_monotonic_ns','finished_monotonic_ns','elapsed_seconds',
                 'timeout_seconds','timed_out','start_error','exit_code','stdout','stderr'),'actual control process fields')
    python=proc['command'][0]
    arguments=[str(script),'--source',str(native_source),'--native-run',str(native_run),'--output',str(run)]
    actual_process(proc,[python,'-I','-B',*arguments],script.parent)
    for name in('stdout','stderr'):same(pin(process_run/name),proc[name],'actual cancellation process '+name)
    same(raw(process_run/'stderr'),b'','cancellation producer stderr')
    result=js(run/'RESULT.json')
    same(strict_json(raw(process_run/'stdout')),result,'actual cancellation producer full stdout')
    fields(result,('actual_elf_processes','control_capture','controls','elapsed_seconds','new_original_processes',
                  'new_original_semantic_cases','original_215_capture_changed','scope_context_wire_observation','status'),
           'complete cancellation control summary')
    same({k:result[k]for k in result if k not in('elapsed_seconds','control_capture')},
         {'status':'PASS','actual_elf_processes':2,'controls':2,'new_original_processes':0,
          'new_original_semantic_cases':0,'original_215_capture_changed':False,'scope_context_wire_observation':False},
         'distinct cancellation control scope')
    same(result['control_capture'],pin(run/'CONTROLS.json'),'whole control result stream')
    remote=js(run/'remote-process.json')
    fields(remote,('pid','argv','cwd','cgroup','started_monotonic_ns'),'actual control producer identity')
    same(remote['pid'],proc['pid'],'actual control PID')
    same(remote['argv'],arguments,'actual cancellation interpreter argv')
    same(remote['cwd'],proc['cwd'],'actual cancellation producer cwd')
    need(type(remote['cgroup'])is str and remote['cgroup'].endswith('\n'),'complete producer cgroup')
    need(proc['started_monotonic_ns']<=remote['started_monotonic_ns']<proc['finished_monotonic_ns'],
         'actual control producer interval')
    need(type(result['elapsed_seconds'])in(int,float) and 0<result['elapsed_seconds']<proc['elapsed_seconds'],
         'actual cancellation producer duration')
    summaries=[];process_ids=[]
    for row in rows:
        case=row['case_id'];folder=run/'sessions'/str(case)
        expected_fields=('after_cancel','after_late','arena_after_cancel','arena_after_late','arena_before_cancel',
            'before','blocked_after_cancel','blocked_before_cancel','blocked_before_transfer','blocked_while_reacquired',
            'cancel','case_id','domain','final_descriptors','fixture_root_hex','input_blobs','input_metadata','key','late',
            'lock_after_cancel','lock_after_late','lock_before_cancel','lock_before_transfer','new_lease_retirement',
            'pending','reacquire_before_late','start','status','transfer','typed')
        fields(row,expected_fields,'complete actual late-worker control')
        same(row['status'],'PASS','control terminal result')
        same(row['domain'],'actual-Linux-cancel-before-late-lock-control','separate control domain')
        fixture=str(run/'files'/('case-'+str(case))).encode()
        same(bytes.fromhex(row['fixture_root_hex']),fixture,'owned actual control fixture')
        session=js(folder/'process.json')
        fields(session,('command','cwd','pid','exit_code','started_monotonic_ns','finished_monotonic_ns','elapsed_seconds',
            'timed_out','start_error','cleanup_killed','terminal_state','request_timeout_seconds','umask',
            'proc_status_at_start','streams'),'complete actual control ELF process')
        same(session['command'],[str(elf),'--async'],'frozen actual control ELF argv')
        same(session['cwd'],str(script.parent),'actual control ELF cwd')
        for field,expected in [('exit_code',0),('timed_out',False),('start_error',None),('cleanup_killed',False),
                                ('terminal_state','exited'),('request_timeout_seconds',60),('umask',0o77)]:
            same(session[field],expected,'actual cancellation process '+field)
        pid=uint(session['pid'],'actual control ELF PID');need(pid>0,'zero control ELF PID')
        process_ids.append(pid)
        begin,end=[uint(session[k],'actual control ELF clock')for k in('started_monotonic_ns','finished_monotonic_ns')]
        need(proc['started_monotonic_ns']<begin<end<proc['finished_monotonic_ns'],'actual child interval')
        same(session['elapsed_seconds'],(end-begin)/1e9,'actual ELF elapsed')
        need(session['elapsed_seconds']<60,'actual ELF control exceeded unchanged request deadline')
        status=raw(folder/'proc-status-at-start.txt')
        same({'bytes':len(status),'sha256':sha(status)},session['proc_status_at_start'],'actual ELF status bytes')
        native.proc_identity(status,pid=pid,parent=proc['pid'],umask=0o77)
        started=js(folder/'started.json')
        same(started,{k:session[k]for k in('command','cwd','pid','started_monotonic_ns','request_timeout_seconds',
                                           'umask','proc_status_at_start')},'actual ELF start receipt')
        streams={}
        for name in('stdin','stdout','stderr'):
            value=gzip.decompress(raw(folder/(name+'.bin.gz')))
            same({'bytes':len(value),'sha256':sha(value)},session['streams'][name],'complete actual control '+name)
            streams[name]=value
        same(streams['stderr'],b'','actual control ELF stderr')
        messages,transactions=native.full_transport(streams['stdin'],streams['stdout'])
        events=native.json_lines(raw(folder/'messages.jsonl'))
        same([{k:v for k,v in e.items()if k!='observed_monotonic_ns'}for e in events],messages,
             'all actual control stdout frames')
        clocks=[e['observed_monotonic_ns']for e in events]
        need(all(type(v)is int and begin<v<end for v in clocks) and clocks==sorted(set(clocks)),
             'actual control receive order/clocks')
        by_offset={e['offset']:e for e in events};tx_by_response={t['messages'][0]['offset']:t for t in transactions}
        def span(frame,request):
            value=native.span(streams['stdin'],request)
            same(value,struct.pack('<Q',len(frame))+frame,'complete actual control request bytes')
            need(begin<=request['started_monotonic_ns']<=request['finished_monotonic_ns']<end,
                 'actual control request write interval')
        def response(event):
            same(event,by_offset[event['offset']],'actual control response record')
            p=event['offset']+16
            return streams['stdout'][p:p+event['payload_bytes']]
        def owner(slot,frame,body,wire,ret):
            fields(wire,('request','response'),'complete private owner wire identity')
            expected=b'HBCFXQ02'+struct.pack('<3Q',slot,len(frame),0)+frame
            span(expected,wire['request'])
            value=response(wire['response'])
            same(value,b'HBCFXR02'+struct.pack('<3Q',slot,ret,len(body))+body,'actual private owner whole response')
            same(tx_by_response[wire['response']['offset']]['request'],expected,'actual owner response request pairing')
            need(wire['request']['finished_monotonic_ns']<=wire['response']['observed_monotonic_ns'],
                 'actual owner response preceded request')
        key=data(row['key']['bytes'])
        typed=data(row['typed'])
        old=native_rows[case]['typed']
        original_typed=gzip.decompress(raw(native_run/'output-async'/old['artifact']))
        same(typed,original_typed,'control reused actual native typed input')
        path=typed[64:64+native.words(typed,16,1)[0]]
        resolved=fixture+b'/'+path
        expected_key_reply=b'HRLKY001'+struct.pack('<3Q',1,len(key),0)+key
        # The complete key response is authoritative; its tag is checked below.
        key_wire=row['key']['wire']
        body=response(key_wire['response'])
        need(body[:8]==b'HBCFXR02'and native.words(body,8,1)[0]==5,'actual key private response')
        key_reply=body[32:];need(key_reply[:8]==b'HRLKY001'and len(key_reply)==32+len(key),'actual complete key reply')
        same(key_reply[32:],key,'actual canonical key bytes')
        owner(5,b'HRLKKEY1'+struct.pack('<7Q',1,len(resolved),0,0,0,0,0)+resolved,
              key_reply,key_wire,len(key_reply))
        start=b'HBCALQ02'+struct.pack('<7Q',1,0,0,len(typed),len(resolved),0,0)+typed+resolved
        same(data(row['start']['frame']),start,'same typed actual control START')
        span(start,row['start']['wire'])
        def returned(record,status,target=None):
            fields(record,('kind','return','status','generation','sequence','target','aux','body','wire'),
                   'complete actual control result')
            body=data(record['body']);same(body,response(record['wire']),'complete actual result wire')
            need(len(body)>=72 and body[8:16]==b'HBCAR002','actual control result magic')
            code=native.words(body,0,1)[0];q=native.words(body,16,7)
            same([record[k]for k in('status','generation','sequence','target')],list(q[:4]),'actual result fields')
            same(record['return'],code,'actual control return code')
            same(record['aux'],q[5],'actual control result auxiliary field')
            need(q[6]==0 and q[4]==len(body)-72,'actual control complete result extent')
            same(record['status'],status,'actual control result status')
            need(record['generation']>0 and record['sequence']>0,'actual result identity')
            if target is not None:same(record['target'],target,'actual pending await target')
            same((record['kind'],record['return']),(3,0xfffffff0)if status==1 else(2,64),'actual result frame kind')
        targets=[2]if case==213 else[2,3,19]
        same(len(row['pending']),len(targets),'actual pending closures')
        for item,target in zip(row['pending'],targets):returned(item,1,target)
        returned(row['cancel'],4,0);returned(row['late'],7,0)
        def lock(record,op,lease=0,key_bytes=b''):
            fields(record,('op','request','response','decoded','wire'),'complete actual lock observation')
            frame=b'HRFLOCK1'+struct.pack('<7Q',op,lease,len(key_bytes),0,0,0,0)+key_bytes
            same(data(record['request']),frame,'same actual lock request')
            value=data(record['response'])
            need(len(value)==64 and value[:8]==b'HRFLKR01','complete lock response')
            q=list(native.words(value,8,7));same(q,record['decoded'],'actual decoded lock fields')
            same(record['op'],op,'actual lock operation')
            same(q[0],op,'actual lock response operation');owner(18,frame,value,record['wire'],64)
            return q
        for name,count in(('lock_before_cancel',1),('lock_after_cancel',0),('lock_before_transfer',0),('lock_after_late',0)):
            same(lock(row[name],7),[7,0,0,0,1,count,0],'actual held-borrow count '+name)
        need(len(row['reacquire_before_late'])==len(row['new_lease_retirement'])==2,'actual complete new lease lifecycle')
        aq=lock(row['reacquire_before_late'][0],1,key_bytes=key);lease=aq[2]
        need(aq[1]==0 and lease>0,'actual post-cancel canonical acquire')
        same(lock(row['reacquire_before_late'][1],3,lease)[1:3],[0,lease],'same canonical key poll succeeded before late')
        same(lock(row['new_lease_retirement'][0],5,lease)[1:3],[0,lease],'actual new lease unlock')
        same(lock(row['new_lease_retirement'][1],6,lease)[1:3],[0,lease],'actual new lease drop')
        for name in('arena_before_cancel','arena_after_cancel','arena_after_late'):
            fields(row[name],('body','wire'),'complete actual lock arena dump')
            owner(18,b'',data(row[name]['body']),row[name]['wire'],0)
        blocked_names=('blocked_before_cancel','blocked_after_cancel','blocked_while_reacquired','blocked_before_transfer')
        worker=None
        for name in blocked_names:
            item=row[name]
            fields(item,('pid','parent','observed_monotonic_ns','children','wchan','syscall','status','fd'),'complete /proc blocked worker')
            if worker is None:worker=uint(item['pid'],'actual blocked child PID')
            same(item['pid'],worker,'same still-running worker')
            same(item['parent'],pid,'actual worker parent')
            same(data(item['children']),(str(worker)+'\n').encode(),'actual exclusive child PID')
            same(data(item['wchan']),b'wait_for_partner','actual still-blocked FIFO kernel wait')
            need(data(item['syscall']).split()[0]==b'257','actual worker syscall was not openat')
            native.proc_identity(data(item['status']),pid=worker,parent=pid,umask=0o77)
            same([f['fd']for f in item['fd']],[0,1,2],'blocked worker descriptor ownership')
            need(begin<item['observed_monotonic_ns']<end,'actual /proc observation interval')
        ordered=[row['pending'][-1]['wire']['observed_monotonic_ns'],
            row['blocked_before_cancel']['observed_monotonic_ns'],row['cancel']['wire']['observed_monotonic_ns'],
            row['blocked_after_cancel']['observed_monotonic_ns'],
            row['reacquire_before_late'][1]['wire']['response']['observed_monotonic_ns'],
            row['blocked_while_reacquired']['observed_monotonic_ns'],
            row['new_lease_retirement'][1]['wire']['response']['observed_monotonic_ns'],
            row['blocked_before_transfer']['observed_monotonic_ns'],row['late']['wire']['observed_monotonic_ns']]
        same(ordered,sorted(set(ordered)),'actual cancellation/reacquire/late temporal order')
        transfer=data(row['transfer'])
        if case==213:
            same(transfer,data(row['input_blobs'][row['input_metadata']['cancel']['transfer_blob']]),'complete late read transfer')
        else:need(len(transfer)>65536,'actual late write spans several kernel pipe windows')
        same(row['before'],row['after_cancel'],'cancel returned before any fixture change')
        same(row['after_cancel'],row['after_late'],'late closure did not resume business mutation')
        for label in('before','after_cancel','after_late'):native.check_tree(files,run,row[label],fixture)
        same([f['fd']for f in row['final_descriptors']],[0,1,2],'actual post-late native FD cleanup')
        # Every input/output transaction is consumed, with no hidden control.
        expected_requests=[b'HBCFXQ02',b'HBCALQ02']+[b'HBCACTL2']*(len(targets)-1)+[
            b'HBCFXQ02',b'HBCFXQ02',b'HBCACTL2',b'HBCFXQ02',b'HBCFXQ02',
            b'HBCFXQ02',b'HBCFXQ02',b'HBCFXQ02',b'HBCFXQ02',b'HBCFXQ02',
            b'HBCACTL2',b'HBCFXQ02',b'HBCFXQ02']
        same([t['request'][:8].decode('ascii')for t in transactions],[v.decode('ascii')for v in expected_requests],
             'all actual control transactions')
        controls=[native.words(t['request'],8,1)[0]for t in transactions if t['request'][:8]==b'HBCACTL2']
        same(controls,[3]*(len(targets)-1)+[2,3],'actual join/cancel/join ordering')
        summaries.append({'case_id':case,'actual_elf_pid':pid,'actual_worker_pid':worker,'transactions':len(transactions),
                          'late_transfer_bytes':len(transfer),'late_transfer_sha256':sha(transfer)})
    need(len(set(process_ids))==2,'actual control processes not distinct')
    for path,value in files.artifacts.items():artifacts[path]=value['sha256']
    return {'schema':'hepta.runtime.batch-call-async-lock-evidence.v1','status':'PASS','controls':2,
            'actual_elf_processes':2,'actual_original_processes':0,'new_original_semantic_cases':0,
            'scope_context_wire_observation':False,'cases':summaries,'new_native_calls':0,'new_rust_processes':0,
            'artifact_sha256':dict(sorted(artifacts.items()))}
