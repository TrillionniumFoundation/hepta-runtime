"""Complete strace admission and source-bound Batch lifetime observations.

Trace strings are explicitly clipped at 128 bytes by the real producer. Full
input, output, snapshots and logical operation payloads are validated separately.
Tokio and HIA are compared at their original completed-operation boundaries; this
reader never claims that their allocator or thread-runtime syscalls are equal.
"""
import collections
import math
import re
import struct
from capture_format import need, same, fields, uint, sha

SYSCALLS = set(('getpgid,openat,read,readv,pread64,write,writev,close,newfstatat,'
    'fstat,statx,readlink,readlinkat,rename,renameat,renameat2,unlink,unlinkat,'
    'mkdir,mkdirat,chmod,fchmod,fchmodat,clone,clone3,wait4,fcntl,lseek,fsync,fdatasync').split(','))
_LINE = re.compile(rb'^([0-9]+) +([0-9]+\.[0-9]+) (.*)$')
_CALL = re.compile(rb'^([a-z0-9_]+)\((.*)\) += (.+) <([0-9]+\.[0-9]+)>$')
_RESULT = re.compile(rb'^(-?[0-9]+)(?:<[^>]*>)?(?: ([A-Z][A-Z0-9_]+) \(([^)]*)\))?$')
_QUOTED = re.compile(rb'"((?:\\x[0-9a-f]{2})*)"( \.\.\.|\.\.\.)?')
_FD = re.compile(rb'^([0-9]+)(?:<([^>]*)>(\(deleted\))?)?(?:,|$)')
_MARKER_BASE = 1000000000


def parse_trace(raw):
    need(type(raw) is bytes and raw and raw.endswith(b'\n'),'complete original trace stream')
    pending = {}
    records = []
    offset = 0
    lines = 0
    for line in raw.splitlines(keepends=True):
        begin = offset
        offset += len(line)
        lines += 1
        need(line.endswith(b'\n'),'trace trailing partial line')
        match = _LINE.fullmatch(line[:-1])
        need(match is not None,'unrecognized full trace line')
        tid = int(match[1])
        stamp = match[2].decode()
        body = match[3]
        need(tid > 0,'zero traced process/thread')
        segment = {'offset':begin,'bytes':len(line),'sha256':sha(line)}
        if body.endswith(b' <unfinished ...>'):
            need(tid not in pending,'second unfinished syscall on one thread')
            head = body[:-len(b' <unfinished ...>')]
            name = re.match(rb'^([a-z0-9_]+)\(',head)
            need(name is not None and name[1].decode() in SYSCALLS,'unknown unfinished syscall')
            pending[tid] = (head,segment,stamp,lines)
            continue
        resumed = re.match(rb'^<\.\.\. ([a-z0-9_]+) resumed>(.*)$',body)
        if resumed:
            need(tid in pending,'resumed syscall has no retained beginning')
            head,first,start_stamp,start_line = pending.pop(tid)
            same(head.split(b'(',1)[0],resumed[1],'resumed syscall name')
            body = head+resumed[2]
            segments = [first,segment]
        else:
            need(tid not in pending,'unfinished syscall was overwritten')
            segments = [segment]
            start_stamp,start_line = stamp,lines
        call = _CALL.fullmatch(body)
        need(call is not None,'incomplete or unknown original syscall result')
        name = call[1].decode()
        need(name in SYSCALLS,'syscall outside exact recorded trace filter')
        result = _RESULT.fullmatch(call[3])
        need(result is not None,'unsupported original syscall return spelling')
        ret = int(result[1])
        err = None if result[2] is None else result[2].decode()
        need((ret == -1) == (err is not None),'missing/unexpected actual OS errno')
        elapsed = float(call[4])
        need(math.isfinite(elapsed) and elapsed >= 0,'nonfinite/negative traced syscall interval')
        records.append({'tid':tid,'name':name,'args':call[2],'return':ret,'errno':err,
            'start_line':start_line,'end_line':lines,'start_timestamp':start_stamp,
            'end_timestamp':stamp,'elapsed_seconds':elapsed,'segments':segments})
    need(not pending and offset==len(raw),'unretired original trace operation')
    need(sum(len(r['segments']) for r in records)==lines,'trace line was discarded')
    markers={}
    marker_order=[]
    for item in records:
        if item['name']=='getpgid':
            need(item['args'].isdigit(),'unexpected marker syscall argument')
            value=int(item['args'])
            need(value>_MARKER_BASE and value not in markers,'duplicate or non-observer marker')
            same((item['return'],item['errno']),(-1,'ESRCH'),'marker actual syscall outcome')
            markers[value]=item
            marker_order.append(value)
    same(marker_order,list(range(_MARKER_BASE+1,_MARKER_BASE+len(markers)+1)),
         'all markers are complete and strictly ordered')
    return {'records':records,'markers':markers,'line_count':lines,'bytes':len(raw),'sha256':sha(raw)}


def quoted(arguments):
    result=[]
    for match in _QUOTED.finditer(arguments):
        hexed=match[1].replace(b'\\x',b'')
        result.append((bytes.fromhex(hexed.decode()),match[2] is not None))
    return result


def has_path(item,path):
    return any(path.startswith(value) if clipped else path==value
               for value,clipped in quoted(item['args']))


def fd_target(arguments):
    match=_FD.match(arguments)
    need(match is not None,'traced descriptor argument syntax')
    value=match[2]
    if value is None:return int(match[1]),None
    # A deleted suffix is annotation, not a pathname supplied to the syscall.
    suffix=b' (deleted)'
    inside_deleted=value.endswith(suffix)
    outside_deleted=match[3] is not None
    need(not(inside_deleted and outside_deleted),'duplicate deleted descriptor annotation')
    if inside_deleted:value=value[:-len(suffix)]
    need(re.fullmatch(rb'(?:\\x[0-9a-f]{2})*',value) is not None,'non-hex decoded FD path')
    return int(match[1]),bytes.fromhex(value.replace(b'\\x',b'').decode())+(suffix if inside_deleted or outside_deleted else b'')


def descriptor_lifetimes(trace):
    live={}
    opens=closes=duplicates=0
    for item in trace['records']:
        name,ret=item['name'],item['return']
        if name=='openat' and ret>=0:
            need(ret not in live,'original reused an owned fd before close')
            live[ret]=item
            opens+=1
        elif name=='fcntl' and ret>=0 and b'F_DUPFD_CLOEXEC' in item['args']:
            fd,_=fd_target(item['args'])
            need(fd in live and ret not in live,'invalid retained-observer FD duplicate')
            live[ret]=item
            duplicates+=1
        elif name=='close' and ret==0:
            fd,_=fd_target(item['args'])
            need(fd in live,'unpaired original close')
            del live[fd]
            closes+=1
    need(not live,'original process ended with an owned traced fd still live')
    same(opens+duplicates,closes,'all traced original opens/duplicates are retired')
    return {'opens':opens,'duplicates':duplicates,'closes':closes,'unretired_descriptors':0}


def interval(trace,enter,leave):
    first=trace['markers'][enter['marker']]
    last=trace['markers'][leave['marker']]
    need(first['end_line']<last['start_line'],'logical event reversed in actual syscall trace')
    return [r for r in trace['records']
            if first['end_line']<r['start_line'] and r['end_line']<last['start_line']]


def matching_exit(events,index,name):
    depth=1
    for at in range(index+1,len(events)):
        kind=events[at]['kind']
        if kind==name+'_enter':depth+=1
        if kind==name+'_exit':
            depth-=1
            if not depth:return events[at]
    return None


def scalar_result(data,get):
    need(type(data.get('ok')) is bool,'logical result boolean type')
    if data['ok']:return {'ok':True}
    need(set(data) in ({'ok','short_blob','kind','errno'},
                      {'ok','short_blob','chain_blob','errno'}),'logical complete error fields')
    get(data['short_blob']).decode('utf-8')
    if 'chain_blob' in data:get(data['chain_blob']).decode('utf-8')
    if data['errno'] is not None:uint(data['errno'],'positive logical errno')
    return {'ok':False,'errno':data['errno']}


def operation_trace(trace,events,get):
    summaries=[]
    for index,enter in enumerate(events):
        kind=enter['kind']
        if kind not in ('exists_enter','tokio_read_enter','tokio_metadata_enter',
                        'tokio_write_enter','tokio_set_permissions_enter','tokio_rename_enter',
                        'tokio_remove_enter'):continue
        name=kind[:-6]
        leave=matching_exit(events,index,name)
        if leave is None:
            # Only the actually aborted read/write future has no completion.
            need(any(x['kind']=='scope_future_drop_cancelled' for x in events[index+1:]),
                 'logical operation lacks completion without actual cancellation')
            need(name in ('tokio_read','tokio_write'),'cancelled non-await operation')
            summaries.append({'operation':name,'enter':enter['marker'],'exit':None,'cancelled':True})
            continue
        rows=interval(trace,enter,leave)
        path=get(enter['data'].get('path_blob',enter['data'].get('from_blob')))
        kinds={'exists':('statx','newfstatat'),'tokio_read':('openat',),
               'tokio_metadata':('statx','newfstatat'),'tokio_write':('openat',),
               'tokio_set_permissions':('chmod','fchmodat'),'tokio_rename':('rename','renameat','renameat2'),
               'tokio_remove':('unlink','unlinkat')}[name]
        actual=[r for r in rows if r['name'] in kinds and has_path(r,path)]
        data=leave['data']
        if b'\0' in path:
            need(not actual,'NUL path reached an OS pathname operation')
            if name=='exists':same(data,{'ok':True,'value':False},'NUL exists result')
            else:same(scalar_result(data,get),{'ok':False,'errno':None},'NUL CString failure')
            summaries.append({'operation':name,'enter':enter['marker'],'exit':leave['marker'],
                              'path_bytes':len(path),'pre_syscall_rejection':True,'syscalls':0})
            continue
        need(actual,'logical original operation is not backed by actual path syscall')
        first=actual[0]
        if name=='exists':
            fields(data,('ok','value'),'actual exists result')
            need(data['ok'] is True and type(data['value']) is bool,'exists typed result')
            same(data['value'],any(r['return']==0 for r in actual),'exists actual OS result')
        elif name in ('tokio_metadata','tokio_set_permissions','tokio_rename','tokio_remove'):
            need(type(data.get('ok')) is bool,'logical operation result type')
            same(data['ok'],actual[-1]['return']==0,'complete logical operation vs actual OS return')
            if not data['ok']:
                need(data['errno'] is not None,'missing actual operation errno')
                import errno
                same(errno.errorcode[data['errno']],actual[-1]['errno'],'actual logical errno')
            if name=='tokio_rename':
                destination=get(enter['data']['to_blob'])
                need(has_path(actual[-1],destination),'actual complete rename destination')
        else:
            if first['return']<0:
                need(data['ok'] is False and data['errno'] is not None,'failed open must remain exact error')
                import errno
                same(errno.errorcode[data['errno']],first['errno'],'actual read/write open errno')
            else:
                fd=first['return']
                transfers=[r for r in rows if r['name']==('read' if name=='tokio_read' else 'write')
                           and _FD.match(r['args']) is not None and int(_FD.match(r['args'])[1])==fd]
                closes=[r for r in rows if r['name']=='close' and int(_FD.match(r['args'])[1])==fd and r['return']==0]
                need(len(closes)==1,'original blocking closure did not close its actual fd')
                if data['ok']:
                    body=get(data['body_blob']) if name=='tokio_read' else get(enter['data']['body_blob'])
                    same(sum(r['return'] for r in transfers if r['return']>=0),len(body),
                         'actual complete read/write byte count')
                    need(not any(r['return']<0 and r['errno']!='EINTR' for r in transfers),
                         'successful logical transfer masked a syscall failure')
                    if name=='tokio_read':need(transfers and transfers[-1]['return']==0,'whole read did not reach EOF')
                elif data['errno'] is not None:
                    import errno
                    need(any(r['return']<0 and r['errno']==errno.errorcode[data['errno']] for r in transfers),
                         'logical read/write errno has no actual syscall')
                else:
                    need(name=='tokio_read' and data.get('kind')=='InvalidData','unexplained read/write error')
                    need(transfers and transfers[-1]['return']==0,'invalid UTF-8 returned before actual EOF')
        summaries.append({'operation':name,'enter':enter['marker'],'exit':leave['marker'],
                          'path_bytes':len(path),'pre_syscall_rejection':False,'syscalls':len(rows)})
    return summaries


def lock_state(value,*,released):
    fields(value,('initialized','poisoned','entries'),'actual original lock observation')
    need(type(value['initialized']) is bool and value['poisoned'] is False and type(value['entries']) is dict,
         'original lock container type/poison state')
    held=[]
    for key,item in value['entries'].items():
        key.encode('utf-8')
        fields(item,('available','strong_count'),'complete observed original lock')
        need(type(item['available']) is bool,'original lock boolean type')
        same(item['strong_count'],1 if item['available'] else 2,'actual lock owner/reference lifetime')
        if not item['available']:held.append(key)
    need(len(held)<=1,'more than one original batch file lock held')
    if released:need(not held,'original lock not released on completion/cancel')
    return held


def descriptors(state,*,native,origin):
    rows=state['descriptors']
    seen=[]
    for row in rows:
        fd=uint(row['fd'],'actual observed fd');seen.append(fd)
        target=bytes.fromhex(row['target_hex'])
        if native:
            fields(row,('fd','target_hex','mode'),'native actual fd observation')
            uint(row['mode'],'native fd mode')
        else:
            fields(row,('fd','target_hex','fixture_owned'),'original actual fd observation')
            need(type(row['fixture_owned']) is bool,'actual fixture-owned descriptor type')
            if fd>2 and not row['fixture_owned']:
                need(re.fullmatch(rb'/proc/[0-9]+/fd',target) is not None,
                     'original retained an unowned operation descriptor')
            if row['fixture_owned']:
                need(fd>2 and target.startswith(origin+b'/'),'fixture descriptor outside owned tree')
    same(seen,sorted(set(seen)),'ordered unique descriptor observation')
    need({0,1,2}<=set(seen),'actual transport descriptors missing')
    if native:same(seen,[0,1,2],'native completed request leaked a descriptor')


def lifecycle(row,meta,get,trace):
    events=row['events']
    need(type(events) is list and events,'missing actual original events')
    for event in events:
        fields(event,('marker','kind','data','request_context','file_locks','session'),'complete event fields')
        marker=uint(event['marker'],'event marker')
        need(marker in trace['markers'],'logical event has no actual marker')
        need(event['session'] is None,'inner fixture gained outer Session semantics')
        context=event['request_context']
        fields(context,('present','hints'),'complete actual request-context observation')
        need(type(context['present']) is bool and type(context['hints']) is list,'typed context state')
        for hint in context['hints']:
            need(type(hint) is str,'non-string hint');hint.encode('utf-8')
        lock_state(event['file_locks'],released=event['kind'] in (
            'case_begin','case_end','execute_batch_edit_exit','scope_exit',
            'scope_future_complete','scope_future_drop_complete','scope_future_drop_cancelled',
            'cancel_after_abort','late_closure_descriptors_closed','followup_begin','followup_end'))
        if event['kind'] in ('scope_first_poll','scope_future_complete','scope_future_drop_complete',
                             'scope_future_drop_cancelled','execute_batch_edit_exit'):
            need(context['present'] is True,'original task-local context not active inside actual future')
        if event['kind'] in ('scope_enter','scope_exit','case_begin','case_end','cancel_before_abort',
                             'cancel_after_abort','late_closure_descriptors_closed','followup_begin','followup_end'):
            need(context['present'] is False,'original task-local context escaped actual future')
        if event['kind'] in ('read_enter','read_exit','history_enter','history_exit','tokio_read_enter',
                             'tokio_read_exit','tokio_metadata_enter','tokio_metadata_exit',
                             'tokio_write_enter','tokio_write_exit','tokio_set_permissions_enter',
                             'tokio_set_permissions_exit','tokio_rename_enter','tokio_rename_exit',
                             'tokio_remove_enter','tokio_remove_exit','note_write_enter','note_write_exit'):
            need(context['present'] is True and len(lock_state(event['file_locks'],released=False))==1,
                 'actual inner I/O/cache operation lacks context or canonical file lock')
    begin=[i for i,e in enumerate(events) if e['kind']=='case_begin']
    end=[i for i,e in enumerate(events) if e['kind']=='case_end']
    need(len(begin)==len(end)==1 and begin[0]<end[0],'case marker boundaries')
    same(events[begin[0]]['data'],{'case_id':meta['case_id'],'entry':'typed-local-inner'},'case entry identity')
    same(events[end[0]]['data'],{'case_id':meta['case_id']},'case exit identity')
    business=events[begin[0]+1:end[0]]
    cancel=meta['execution']=='async'
    if cancel:
        required=('cancel_before_abort','scope_future_drop_cancelled','cancel_after_abort',
                  'late_closure_descriptors_closed','followup_begin','followup_end')
        positions=[]
        for name in required:
            pos=[i for i,e in enumerate(business) if e['kind']==name]
            need(len(pos)==1,'missing/duplicate actual cancel lifetime event '+name)
            positions.append(pos[0])
        same(positions,sorted(positions),'cancel/drop/late/followup event order')
        first=business[:positions[4]]
        following=business[positions[4]+1:positions[5]]
        need(not any(e['kind'] in ('execute_batch_edit_exit','scope_future_complete','scope_exit')
                     for e in first),'cancelled original produced a normal result')
        barrier=row['result']['barrier']
        fields(barrier,('tid','wchan_blob','syscall_blob'),'actual blocked closure barrier')
        need(uint(barrier['tid'],'actual blocked thread')>0,'zero blocked thread')
        need(b'wait_for_partner' in get(barrier['wchan_blob']),'cancel did not observe blocking FIFO open')
        syscall=get(barrier['syscall_blob'])
        need(syscall.split() and syscall.split()[0]==b'257','cancel barrier is not actual openat')
        same(business[positions[0]]['data'],{'stage':meta['cancel']['stage'],'barrier':barrier},
             'actual cancel barrier identity')
        # The awaited task was dropped while its started OS closure remained live.
        blocked=[r for r in trace['records'] if r['tid']==barrier['tid'] and r['name']=='openat'
                 and r['start_line']<trace['markers'][business[positions[0]]['marker']]['start_line']]
        need(blocked,'blocked original worker has no actual openat')
        before=trace['markers'][business[positions[0]]['marker']]['start_line']
        after=trace['markers'][business[positions[2]]['marker']]['end_line']
        need(any(r['start_line']<before<after<r['end_line'] and len(r['segments'])==2 for r in blocked),
             'actual started syscall did not survive handler abort')
        need(row['result']['cancelled'] is True and row['result']['normal_original_result_received'] is False,
             'cancelled original result was relabelled as success')
        lock_state(row['result']['after_cancel']['file_locks'],released=True)
        lock_state(row['result']['after_late']['file_locks'],released=True)
    else:
        first=business;following=[]
        need(not any(e['kind'].startswith('cancel_') or e['kind']=='scope_future_drop_cancelled'
                     for e in business),'ordinary original record contains cancellation')
    for segment in ([following] if cancel else [first]):
        lifecycle_names=[e['kind'] for e in segment if e['kind'].startswith('scope_')]
        same(lifecycle_names,['scope_enter','scope_first_poll','scope_future_complete',
                              'scope_future_drop_complete','scope_exit'],'complete actual request scope lifecycle')
        exits=[e for e in segment if e['kind']=='execute_batch_edit_exit']
        need(len(exits)==1,'completed future has missing/duplicate original body')
        desired=row['result']['followup']['result'] if cancel else row['result']
        value=exits[0]['data']
        need(type(desired['ok']) is bool and desired['ok']==value['ok'],'original wrapper success identity')
        if value['ok']:
            hints=exits[0]['request_context']['hints']
            dedup=list(dict.fromkeys(hints))
            body=get(value['body_blob'])
            if dedup:body+=b'\n\n'+b''.join(b'\xe2\x9a\xa0\xef\xb8\x8f '+h.encode()+b'\n' for h in dedup)
            same(body,get(desired['body_blob']),'actual append_hints complete body')
        else:same(get(value['short_blob']),get(desired['body_blob']),'actual error bypasses hint append')
    lock_state(row['before']['file_locks'],released=True)
    lock_state(row['after']['file_locks'],released=True)
    need(row['request_context_present_after'] is False,'request context remained after final completion')
    return first,following


def stage_observations(events):
    kinds={'exists_exit':'exists','read_exit':'read','history_exit':'history',
           'tokio_metadata_exit':'atomic_metadata','tokio_write_exit':'atomic_write',
           'tokio_set_permissions_exit':'atomic_permissions','tokio_rename_exit':'atomic_rename',
           'tokio_remove_exit':'atomic_cleanup','note_write_exit':'note_write'}
    return [(kinds[e['kind']],e) for e in events if e['kind'] in kinds]
