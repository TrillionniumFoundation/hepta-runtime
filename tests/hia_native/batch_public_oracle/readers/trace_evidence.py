"""Complete kernel streams and actual observed public Batch lifetimes.

The real strace producers use a 4096-byte string display bound. Complete pipe
streams are independently retained. No allocator/thread syscall equivalence or
unrecorded inner-HIA completion event is inferred from the outer receipts.
"""
import collections,errno,math,re,struct
from capture_format import need,same,fields,uint,sha
_LINE=re.compile(rb'^([0-9]+) +([0-9]+\.[0-9]+) (.*)$')
_CALL=re.compile(rb'^([a-z0-9_]+)\((.*)\) += (.+?)(?: <([0-9]+\.[0-9]+)>)?$')
_RESULT=re.compile(rb'^(-?(?:0x[0-9a-f]+|[0-9]+))(?:<[^>]*>)?(?: ([A-Z][A-Z0-9_]+) \((.*)\))?$')
_QUOTED=re.compile(rb'"((?:\\x[0-9a-f]{2})*)"( \.\.\.|\.\.\.)?')
_FD=re.compile(rb'^([0-9]+)(?:<([^>]*)>(\(deleted\))?)?(?:,|$)')
_ALLOWED=set(('execve execveat access faccessat faccessat2 open openat openat2 read write readv writev close fstat stat lstat newfstatat statx getpgid getdents64 flock fcntl dup dup2 dup3 clone clone3 fork vfork wait4 waitid mmap mremap munmap fsync fdatasync fchmod fchown getrandom clock_gettime gettimeofday exit exit_group readlink readlinkat getcwd chdir fchdir mkdir mkdirat rmdir rename renameat renameat2 unlink unlinkat chmod fchmodat chown lchown fchownat link linkat symlink symlinkat umask statfs fstatfs utimensat').split())
def parse_trace(raw,*,markers):
 need(type(raw)is bytes and raw and raw.endswith(b'\n'),'complete actual kernel trace')
 pending={};records=[];offset=0;signals=[];lines=0
 for line in raw.split(b'\n')[:-1]:
  line+=b'\n';lines+=1;begin=offset;offset+=len(line);match=_LINE.fullmatch(line[:-1]);need(match is not None,'unknown complete trace line')
  tid=int(match[1]);stamp=match[2].decode();body=match[3];need(tid>0,'positive actual traced TID')
  segment={'offset':begin,'bytes':len(line),'sha256':sha(line)}
  if body.startswith(b'--- '):
   need(re.fullmatch(rb'--- SIGCHLD \{.*si_code=CLD_EXITED,.*si_status=0,.*\} ---',body)is not None,'unexpected actual process signal')
   signals.append({'tid':tid,'line':lines,'raw':body.decode(),'segment':segment});continue
  if body.startswith(b'+++ '):
   need(body==b'+++ exited with 0 +++','actual process failed in trace')
   signals.append({'tid':tid,'line':lines,'raw':body.decode(),'segment':segment});continue
  if body.endswith(b' <unfinished ...>'):
   need(tid not in pending,'overwritten pending syscall');head=body[:-len(b' <unfinished ...>')]
   name=re.match(rb'^([a-z0-9_]+)\(',head);need(name is not None and name[1].decode()in _ALLOWED,'unknown actual pending syscall')
   pending[tid]=(head,segment,stamp,lines);continue
  resumed=re.fullmatch(rb'<\.\.\. ([a-z0-9_]+) resumed>(.*)',body)
  if resumed:
   need(tid in pending,'resumed syscall has no actual start');head,first,start_stamp,start_line=pending.pop(tid)
   same(head.split(b'(',1)[0],resumed[1],'actual resumed syscall name');body=head+resumed[2];segments=[first,segment]
  else:
   need(tid not in pending,'pending syscall discarded');segments=[segment];start_stamp,start_line=stamp,lines
  call=_CALL.fullmatch(body);need(call is not None,'incomplete actual syscall result')
  name=call[1].decode();need(name in _ALLOWED,'syscall outside declared actual filter')
  if name in ('exit','exit_group'):
   need(call[3]==b'?' and call[2]==b'0','actual successful process exit')
   ret=None;err=None
  else:
   result=_RESULT.fullmatch(call[3]);need(result is not None,'unsupported actual return '+name+' '+repr(call[3]))
   ret=int(result[1],16 if b'0x'in result[1]else 10);err=None if result[2]is None else result[2].decode()
   need((ret==-1)==(err is not None),'actual errno/return mismatch')
   need(call[4]is not None,'actual syscall elapsed missing')
  elapsed=None if call[4]is None else float(call[4]);need(elapsed is None or math.isfinite(elapsed)and elapsed>=0,'actual finite syscall elapsed')
  records.append({'tid':tid,'name':name,'args':call[2],'return':ret,'errno':err,'start_line':start_line,'end_line':lines,'start_timestamp':start_stamp,'end_timestamp':stamp,'elapsed_seconds':elapsed,'segments':segments})
 need(not pending and offset==len(raw),'unretired actual syscall')
 need(sum(len(x['segments'])for x in records)+len(signals)==lines,'dropped kernel trace line')
 found={};ordered=[]
 for r in records:
  if r['name']=='getpgid':
   need(markers and r['args'].isdigit(),'unexpected marker syscall')
   n=int(r['args']);need(n>1000000000 and n not in found,'duplicate invalid observer marker')
   same((r['return'],r['errno']),(-1,'ESRCH'),'actual observer marker outcome')
   found[n]=r;ordered.append(n)
 if markers:same(ordered,list(range(1000000001,1000000001+len(found))),'complete original observer order')
 need(any(r['name']=='execve'and r['return']==0 for r in records),'actual ELF exec missing')
 need(any(r['name']in('exit','exit_group')for r in records),'actual successful EOF exit missing')
 return {'records':records,'markers':found,'signals':signals,'line_count':lines,'bytes':len(raw),'sha256':sha(raw)}
def bytes_arguments(arguments):
 return [(bytes.fromhex(m[1].replace(b'\\x',b'').decode()),m[2]is not None)for m in _QUOTED.finditer(arguments)]
def fd_number(arguments):
 m=_FD.match(arguments);need(m is not None,'actual descriptor argument');return int(m[1])
def stream_evidence(trace,*,stdin,stdout,stderr):
 desired={('read',0):stdin,('write',1):stdout,('write',2):stderr};position={k:0 for k in desired};rows={k:[]for k in desired};eof=False
 for r in trace['records']:
  if r['name']not in ('read','write')or _FD.match(r['args'])is None:continue
  key=r['name'],fd_number(r['args'])
  if key not in desired:continue
  n=r['return']
  if n<0:need(r['errno']=='EINTR','actual pipe operation failed');continue
  if n==0:
   if key==('read',0):eof=True
   continue
  values=bytes_arguments(r['args']);need(values,'actual pipe data spelling')
  data,clipped=values[0];at=position[key];part=desired[key][at:at+n]
  need(len(part)==n,'kernel pipe wrote/read beyond retained complete stream')
  if clipped:need(len(data)<n and part.startswith(data),'actual clipped kernel prefix')
  else:same(data,part,'actual full kernel pipe payload')
  position[key]+=n;rows[key].append({**r,'stream_offset':at,'stream_bytes':n,'clipped':clipped})
 need(position=={k:len(v)for k,v in desired.items()},'all actual pipe bytes accounted')
 need(eof,'actual input EOF missing')
 return {'rows':rows,'counts':{name:len(rows[key])for name,key in [('stdin',('read',0)),('stdout',('write',1)),('stderr',('write',2))]},'bytes':{'stdin':len(stdin),'stdout':len(stdout),'stderr':len(stderr)}}
def exchange_interval(trace,streams,exchange):
 inp=exchange['accepted_input'];out=exchange['response']
 begin=next((r for r in streams['rows'][('read',0)]if r['stream_offset']<inp['offset']+inp['bytes']<=r['stream_offset']+r['stream_bytes']),None)
 end=next((r for r in streams['rows'][('write',1)]if r['stream_offset']<=out['offset']<r['stream_offset']+r['stream_bytes']),None)
 need(begin is not None and end is not None and begin['end_line']<end['start_line'],'actual request precedes response')
 return [r for r in trace['records']if begin['end_line']<r['start_line']and r['end_line']<end['start_line']]
def descriptor_lifetimes(trace,origin):
 parents={};tables={};table_users={};opened=closed=cloned=unknown_closes=0;implicit=[]
 creating=set();private_copies=[];changes=[];owner_closes={};inherited_exits=[];exits={};waits={}
 for r in trace['records']:
  if r['name']in('clone','clone3','fork','vfork')and r['return']is not None and r['return']>0:
   child=r['return'];need(child!=r['tid']and child not in parents,'ambiguous actual child creation')
   parents[child]=(r['tid'],b'CLONE_FILES'in r['args'],r)
 def table(tid):
  nonlocal cloned
  if tid in tables:return tables[tid]
  need(tid not in creating,'cyclic actual process parentage');creating.add(tid)
  if tid in parents:
   parent,shared,creation=parents[tid];p=table(parent)
   t=p if shared else {fd:dict(value,inherited=True,copy_parent=parent,copy_child=tid,
                              clone_start_line=creation['start_line'],clone_end_line=creation['end_line'])
                        for fd,value in p.items()}
   if not shared:
    cloned+=len(t);private_copies.append((p,creation))
  else:t={}
  tables[tid]=t;table_users.setdefault(id(t),set()).add(tid);creating.remove(tid);return t
 for r in trace['records']:
  # Records arrive in completion order.  Normally a child is installed at the
  # successful creation record.  With <unfinished>/<resumed>, its first visible
  # completed syscall can precede that record: create it lazily at that point,
  # using the already-observed parent table, and never copy it a second time.
  # Pre-creating every table before the loop loses all pre-clone open FDs.
  t=table(r['tid']);name,n=r['name'],r['return']
  if name in('clone','clone3','fork','vfork')and n is not None and n>0:
   table(n)
  elif name in('open','openat','openat2')and n>=0:
   need(n not in t,'file descriptor reused before retirement')
   paths=bytes_arguments(r['args']);need(paths,'actual open pathname')
   t[n]={'path':paths[0][0],'origin':r['start_line'],'owner':(r['tid'],r['start_line'],n),
         'inherited':False};opened+=1;changes.append((t,r))
  elif name in('dup','dup2','dup3')and n>=0 or name=='fcntl'and n>=0 and b'F_DUPFD'in r['args']:
   fd=fd_number(r['args'])
   if fd in t:
    need(n not in t or name in('dup2','dup3'),'dup overwrote actual live file descriptor')
    if n!=fd:
     source=t[fd]
     if n in t and not t[n]['inherited']:owner_closes[t[n]['owner']]=r
     t[n]={'path':source['path'],'origin':r['start_line'],'owner':(r['tid'],r['start_line'],n),
           'inherited':False};opened+=1
   changes.append((t,r))
  elif name=='close'and n==0:
   fd=fd_number(r['args'])
   if fd in t:
    if not t[fd]['inherited']:owner_closes[t[fd]['owner']]=r
    del t[fd];closed+=1
   else:unknown_closes+=1
   changes.append((t,r))
  elif name in('exit','exit_group'):
   need(r['tid']not in exits,'duplicate actual process exit');exits[r['tid']]=r
   users=table_users[id(t)];users.discard(r['tid'])
   if not users:
    for fd,v in t.items():
     if v['inherited']:inherited_exits.append((fd,v,r))
     else:
      need(not v['path'].startswith(origin+b'/'),'owned fixture file descriptor leaked until kernel exit')
      implicit.append({'fd':fd,'path_hex':v['path'].hex(),'exit_tid':r['tid']})
    t.clear()
  elif name=='wait4'and n is not None and n>0:
   waits.setdefault(n,[]).append(r)
 # A private fork copies its parent's table somewhere within the recorded
 # creation interval.  If another thread sharing that parent table mutates it
 # during that interval, this trace alone cannot determine the inherited set.
 # Refuse that ambiguity rather than silently assert an empty/exact copy.
 for parent,creation in private_copies:
  for changed,event in changes:
   if changed is parent:
    need(not(event['start_line']<creation['end_line']and event['end_line']>creation['start_line']),
         'ambiguous private FD inheritance during concurrent parent-table mutation')
 reaps={}
 for parent,creation in private_copies:
  child=creation['return'];need(child in exits,'private child exit missing from complete trace')
  selected=waits.get(child,[]);need(len(selected)==1,'private child successful wait4 retirement missing or duplicated')
  waited=selected[0];ended=exits[child]
  need(waited['tid']==creation['tid']and waited['args'].split(b',',1)[0]==str(child).encode()and
       b'[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]'in waited['args']and
       creation['start_line']<=waited['start_line']and ended['end_line']<waited['end_line'],
       'private child was not actually joined by its creator after successful exit')
  reaps[child]={'parent_tid':creation['tid'],'child_tid':child,'clone_start_line':creation['start_line'],
                'clone_end_line':creation['end_line'],'exit_line':ended['end_line'],
                'wait_start_line':waited['start_line'],'wait_end_line':waited['end_line']}
 inherited=[]
 for fd,value,ended in inherited_exits:
  need(value['owner']in owner_closes,'inherited descriptor owner was not explicitly retired')
  owner_close=owner_closes[value['owner']];reap=reaps[value['copy_child']]
  need(ended['end_line']<reap['wait_end_line'],'inherited reference survived its observed child join')
  inherited.append({'fd':fd,'path_hex':value['path'].hex(),'owner_tid':value['owner'][0],
                    'owner_open_line':value['owner'][1],'owner_fd':value['owner'][2],
                    'owner_close_tid':owner_close['tid'],'owner_close_line':owner_close['end_line'],
                    'copy_parent_tid':value['copy_parent'],'copy_child_tid':value['copy_child'],
                    'clone_start_line':value['clone_start_line'],'clone_end_line':value['clone_end_line'],
                    'exit_tid':ended['tid'],'exit_line':ended['end_line'],'wait_end_line':reap['wait_end_line']})
 need(all(not t for t in tables.values()),'traced file descriptor table remained live')
 return {'actual_opens_or_duplicates':opened,'explicit_traced_file_closes':closed,'inherited_file_copies':cloned,
         'other_runtime_or_borrowed_closes':unknown_closes,'implicit_nonfixture_retirements':implicit,
         'implicit_inherited_retirements':inherited,'nonshared_child_reaps':list(reaps.values()),
         'unretired_fixture_descriptors':0}
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

def actual_file_transfers(rows,origin):
 """Completed file-data closures, excluding libc/Tokio implementation details."""
 live={};answer=[]
 for r in rows:
  name,n=r['name'],r['return']
  if name in('open','openat','openat2'):
   q=bytes_arguments(r['args']);path=q[0][0]if q else None
   if path is None or not path.startswith(origin+b'/')or b'O_DIRECTORY'in r['args']:continue
   if n>=0:
    key=r['tid'],n;need(key not in live,'unclosed same-thread data descriptor')
    live[key]={'path':path,'reads':[],'writes':[]}
   continue
  if name in('read','write','close')and _FD.match(r['args'])is not None:
   fd=fd_number(r['args']);key=r['tid'],fd;owner=live.get(key)
   if owner is None:
    possible=[k for k in live if k[1]==fd]
    if len(possible)==1:key=possible[0];owner=live[key]
   if owner is None:continue
   if name=='close':
    need(n==0,'actual file closure failed')
    for label in ('reads','writes'):
     ops=owner[label]
     if ops:answer.append({'operation':'read'if label=='reads'else'write','path_hex':owner['path'].hex(),'body_hex':b''.join(x[0]for x in ops if x[1]>0).hex(),'eof':label=='reads'and ops[-1][1]==0,'errno':[x[2]for x in ops if x[1]<0]})
    del live[key]
   else:
    q=bytes_arguments(r['args']);body=b''
    if n>0:
     need(q and not q[0][1]and len(q[0][0])==n,'business data is not completely displayed by this corpus trace');body=q[0][0]
    owner['reads'if name=='read'else'writes'].append((body,n,r['errno']))
  elif name in('rename','renameat','renameat2'):
   q=bytes_arguments(r['args'])
   if q and q[0][0].startswith(origin+b'/'):
    need(len(q)==2 and not any(c for _,c in q),'complete actual rename paths')
    answer.append({'operation':'rename','from_hex':q[0][0].hex(),'to_hex':q[1][0].hex(),'return':n,'errno':r['errno']})
  elif name in('chmod','fchmodat'):
   q=bytes_arguments(r['args'])
   if q and q[0][0].startswith(origin+b'/'):
    mode=r['args'].rsplit(b', ',1)[-1];need(re.fullmatch(rb'[0-7]+',mode)is not None,'actual chmod mode')
    answer.append({'operation':'chmod','path_hex':q[0][0].hex(),'mode':int(mode,8),'return':n,'errno':r['errno']})
 need(all(not x['reads']and not x['writes']for x in live.values()),'data file still open at reply')
 return answer
def native_receipts(raw):
 lengths={b'HRGTR002':224,b'HRCNAK02':128,b'HFLKEYFX':128};at=0;counts=collections.Counter();rows=[]
 while at<len(raw):
  magic=raw[at:at+8];need(magic in lengths,'unknown native receipt family');n=lengths[magic];part=raw[at:at+n];need(len(part)==n,'partial native receipt')
  counts[magic.decode()]+=1;values=struct.unpack('<'+'Q'*(n//8-1),part[8:])
  if magic==b'HRGTR002':
   seq,slot,event,ret,wcap,ocap,phase,owner_seq,extent=values[:9]
   need(0<=slot<=36 and event in(1,2,3,4)and seq>0,'outer receipt slot/event/sequence')
   need(wcap>=4096 and ocap>=4096 and wcap%4096==ocap%4096==0,'actual outer capacities')
   if event==2:same(ret,0,'actual mechanical resize result')
   if event==1:need(ret<1<<32,'zero-extended HIA return')
  rows.append({'offset':at,'bytes':n,'magic':magic.decode(),'words':list(values),'sha256':sha(part)});at+=n
 need(at==len(raw),'native receipt stream tail')
 return {'counts':dict(counts),'rows':rows}

def public_lifecycle(meta,step,get,trace):
 events=meta['events'];need(type(events)is list and len(events)>=2,'complete actual public events')
 kinds=[e['kind']for e in events]
 same(kinds[0],'public_case_begin','actual public entry');same(kinds[-1],'public_case_end','actual public exit')
 same(events[0]['data'],{'case_id':step['case_id']},'actual public case identity')
 same(events[-1]['data'],{'case_id':step['case_id']},'actual public completion identity')
 for e in events:
  fields(e,('marker','kind','data','request_context','file_locks','session'),'complete event observation')
  need(uint(e['marker'],'actual marker')in trace['markers'],'event has no actual kernel marker')
  context=e['request_context'];fields(context,('present','hints'),'actual task-local observation')
  need(type(context['present'])is bool and type(context['hints'])is list and all(type(x)is str for x in context['hints']),'typed context/hints')
  if e['kind']in('public_case_begin','public_case_end','outer_call_tool_enter','handler_enter','handler_exit','scope_enter','scope_exit','effect_fence_enter','effect_fence_exit','policy_lookup','local_policy_enter','local_policy_exit'):
   need(context['present']is False,'request context escaped future')
  if e['kind']in('scope_first_poll','scope_future_complete','scope_future_drop_complete'):
   need(context['present']is True,'scope not active in polled future')
  released=e['kind']in('public_case_begin','public_case_end','handler_enter','handler_exit','scope_future_complete','scope_future_drop_complete','scope_exit')
  held=lock_state(e['file_locks'],released=released)
  if e['kind']in('read_enter','read_exit','tokio_read_enter','tokio_read_exit','history_enter','history_exit','tokio_metadata_enter','tokio_metadata_exit','tokio_write_enter','tokio_write_exit','tokio_set_permissions_enter','tokio_set_permissions_exit','tokio_rename_enter','tokio_rename_exit','note_write_enter','note_write_exit'):
   need(context['present']is True and len(held)==1,'actual file stage lacks scope/canonical lock')
  need(e['session']is not None,'actual watched Session missing')
  state=e['session'];fields(state,('root_blob','current_blob','effective_blob','poisoned','latched'),'actual event Session')
  need(type(state['poisoned'])is bool and type(state['latched'])is bool,'typed actual Session')
  get(state['root_blob']);get(state['effective_blob'])
  if state['current_blob']is not None:get(state['current_blob'])
 same(uint(meta['outer_call_tool_entries'],'actual outer entries'),kinds.count('outer_call_tool_enter'),'outer count from markers')
 same(uint(meta['handler_entries'],'actual typed handler entries'),kinds.count('handler_enter'),'handler count from markers')
 same(kinds.count('handler_enter'),kinds.count('handler_exit'),'handler completed')
 need(kinds.count('handler_enter')<=1 and kinds.count('outer_call_tool_enter')<=1,'duplicate handler')
 if 'handler_enter'in kinds:
  at=kinds.index('handler_enter');same(kinds[at+1:at+3],['effect_fence_enter','effect_fence_exit'],'fence-before-session/policy order')
  fence=events[at+2]['data'];need(type(fence['ok'])is bool,'actual fence result')
  if not fence['ok']:same(kinds[at+3:],['handler_exit','public_case_end'],'failed fence stopped handler')
  if 'scope_enter'in kinds:
   same([k for k in kinds if k.startswith('scope_')],['scope_enter','scope_first_poll','scope_future_complete','scope_future_drop_complete','scope_exit'],'actual scope/drop lifecycle')
   need(kinds.index('scope_exit')<kinds.index('handler_exit')and kinds.index('scope_enter')>at+2,'scope ordering')
 else:
  if step['action']['kind']=='public':need(set(kinds)<={'public_case_begin','public_case_end','outer_call_tool_enter'},'typed/metadata rejection entered business owner')
 if step['action']['kind']=='cache_seed':
  same(kinds,['public_case_begin','scope_enter','scope_first_poll','scope_future_complete','scope_future_drop_complete','scope_exit','public_case_end'],'real cache seed scope')
 if 'note_write_enter'in kinds:
  need('tokio_rename_exit'in kinds and kinds.index('tokio_rename_exit')<kinds.index('note_write_enter'),'cache before atomic rename')
  need(events[kinds.index('tokio_rename_exit')]['data']['ok']is True,'cache after failed atomic publication')
 if 'tokio_write_enter'in kinds:need('history_exit'in kinds and kinds.index('history_exit')<kinds.index('tokio_write_enter'),'write before history')
 for k in('effect_fence','local_policy','remote_policy','exists','read','history','tokio_read','tokio_metadata','tokio_write','tokio_set_permissions','tokio_rename','note_write'):
  same(kinds.count(k+'_enter'),kinds.count(k+'_exit'),'completed stage pair '+k)
 need(meta['request_context_present_after']is False and meta['original_full_router_executed']is False,'scope/full-router boundary')
 lock_state(meta['before']['file_locks'],released=True);lock_state(meta['after']['file_locks'],released=True)
 return operation_trace(trace,events,get)
