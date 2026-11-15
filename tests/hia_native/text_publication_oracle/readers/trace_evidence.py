"""Consume every original strace line; delimit unchanged publication calls."""
import re,os
from common import require,pin,integer
# strace pads a short PID column with ASCII spaces (for example "5499  ").
# Keep the timestamp and complete syscall body separate; do not strip records.
LINE=re.compile(r'^(\d+) +(\d+\.\d+) (.*)$')
CALL=re.compile(r'^([a-z][a-z0-9_]*)\((.*)\)\s+=\s+(.*?)\s+<(\d+\.\d+)>$')
ALLOWED={'getpgid','open','openat','close','read','write','readv','writev','lseek','newfstatat','fstat','statx','flock','flistxattr','geteuid','getrandom','fchmod','fsync','fdatasync','renameat','renameat2','unlinkat','fcntl','dup','dup2','dup3','exit','exit_group'}
def split_args(raw):
    result=[];start=0;quoted=False;escape=False;stack=[];pairs={')':'(',']':'[','}':'{','>':'<'}
    for i,c in enumerate(raw):
        if quoted:
            if escape:escape=False
            elif c=='\\':escape=True
            elif c=='"':quoted=False
            continue
        if c=='"':quoted=True;continue
        if c in '([{<':stack.append(c)
        elif c in ')]}>':
            require(stack and stack.pop()==pairs[c],'balanced actual trace argument')
        elif c==',' and not stack:result.append(raw[start:i].strip());start=i+1
    require(not quoted and not stack,'complete original syscall argument text')
    if raw:result.append(raw[start:].strip())
    return result
def fd(token):
    match=re.match(r'^(-?\d+)(?:<.*>)?(?:\(deleted\))?$',token)
    require(match is not None,'actual numeric descriptor argument')
    return int(match[1])
def quoted(token):
    match=re.match(r'^"((?:\\x[0-9a-f]{2})*)"(.*)$',token)
    require(match is not None,'actual -xx quoted byte string')
    raw=bytes.fromhex(match[1].replace('\\x',''))
    tail=match[2];require(tail in ('','...'),'actual string truncation suffix')
    return raw,bool(tail)
def stat_record(raw):
    require(raw.startswith('{') and raw.endswith('}') and '...' not in raw,'complete original stat structure')
    dev=re.search(r'\bst_dev=makedev\((0x[0-9a-f]+|\d+), (0x[0-9a-f]+|\d+)\)',raw)
    require(dev is not None,'actual device components')
    def field(name):
        found=re.findall(r'\b'+name+r'=(-?\d+)(?=[, }])',raw)
        require(len(found)==1,'complete unique original stat field')
        return int(found[0])
    mode=re.search(r'\bst_mode=(S_IF[A-Z]+)((?:\|[A-Z0-9_]+)*)\b',raw)
    require(mode is not None,'actual complete file mode')
    parts=mode[2].split('|')[1:];mode_value=0;symbols={'S_ISUID':0o4000,'S_ISGID':0o2000,'S_ISVTX':0o1000}
    require(len(parts)==len(set(parts)),'unique actual permission tokens')
    for part in parts:
        require(part in symbols or re.fullmatch('[0-7]+',part) is not None,'known complete permission token')
        mode_value|=symbols[part] if part in symbols else int(part,8)
    require(mode_value<=0o7777,'actual permission mask')
    values=[os.makedev(int(dev[1],0),int(dev[2],0)),field('st_ino'),field('st_size'),
        field('st_mtime'),field('st_mtime_nsec'),field('st_ctime'),field('st_ctime_nsec')]
    require(0<=values[4]<10**9 and 0<=values[6]<10**9,'actual full stat nanoseconds')
    return {'version':values,'kind':mode[1],'mode':mode_value,'nlink':field('st_nlink'),'uid':field('st_uid'),'gid':field('st_gid')}
def evidence(raw,expected_ids,results):
    require(raw.endswith(b'\n'),'complete trace final line')
    lines=raw.decode('ascii').splitlines();active=None;seen=[];cases={};opened={};pid=None;total=0;outside=0;terminated=False
    operation_counts={}
    for line_number,line in enumerate(lines,1):
        match=LINE.fullmatch(line);require(match is not None,'complete trace PID/time line')
        actual_pid=int(match[1]);stamp=match[2];body=match[3]
        if pid is None:pid=actual_pid
        require(actual_pid==pid,'single synchronous original process')
        if body.startswith('+++ exited with '):
            require(body=='+++ exited with 0 +++' and active is None and not opened,'actual clean original exit')
            terminated=True;continue
        require(not terminated,'trace after terminal exit')
        call=CALL.fullmatch(body)
        if call is None and re.fullmatch(r'exit_group\(0\)\s+=\s+\?',body):
            require(active is None and not opened,'clean original exit_group')
            total+=1;outside+=1;continue
        require(call is not None,'unparsed original trace line')
        name,argtext,result,duration=call.groups()
        require(name in ALLOWED,'unknown actual traced syscall')
        args=split_args(argtext);total+=1
        if result=='?':
            require(name in ('exit','exit_group') and active is None and not opened,'unknown unfinished original syscall')
            outside+=1;continue
        number=re.match(r'^(-?\d+)',result);require(number is not None,'actual syscall return')
        ret=int(number[1]);errno=None
        if ret==-1:
            error=re.match(r'^-1 ([A-Z0-9]+) \(',result);require(error is not None,'actual OS error return');errno=error[1]
        row={'line':line_number,'pid':pid,'timestamp':stamp,'name':name,'arguments':args,'return':ret,'errno':errno,'duration':duration}
        if name in ('fstat','newfstatat') and ret==0:
            row['stat']=stat_record(args[1 if name=='fstat' else 2])
        if name=='getpgid':
            require(len(args)==1 and errno=='ESRCH' and ret==-1,'actual marker syscall observation')
            marker=int(args[0]);require(marker>=900000000,'actual marker namespace')
            case_id,end=divmod(marker-900000000,2)
            if not end:
                require(active is None and not opened and len(seen)<len(expected_ids) and expected_ids[len(seen)]==case_id,'unique ordered begin marker')
                active=case_id;cases[case_id]={'begin':row,'syscalls':[]}
            else:
                require(active==case_id and not opened,'ordered end marker after all descriptor retirement')
                cases[case_id]['end']=row;seen.append(case_id);active=None
            continue
        if name in ('open','openat') and ret>=0:
            require(ret not in opened,'opened descriptor is newly owned')
            opened[ret]={'line':line_number,'owner':active,'name':name,'arguments':args}
            row['descriptor_opened']=ret
        elif name=='close':
            require(len(args)==1,'close argument count')
            value=fd(args[0])
            if ret==0:
                require(value in opened,'close of traced owned descriptor')
                old=opened.pop(value);row['descriptor_closed']=value;row['opened_at_line']=old['line']
                require(old['owner']==active,'descriptor lifetime crossed original marker')
        elif name in ('dup','dup2','dup3') and ret>=0:
            require(ret not in opened,'new duplicate descriptor')
            opened[ret]={'line':line_number,'owner':active,'name':name,'arguments':args}
        if active is None:outside+=1
        else:
            cases[active]['syscalls'].append(row);operation_counts[name]=operation_counts.get(name,0)+1
    require(active is None and not opened and seen==list(expected_ids),'all trace markers and descriptors fully consumed')
    outputs=[]
    for case_id in expected_ids:
        entry=cases[case_id];calls=entry['syscalls'];answer=results[case_id]
        opens=[c for c in calls if 'descriptor_opened' in c];closes=[c for c in calls if 'descriptor_closed' in c]
        require(len(opens)==len(closes),'per-publication owned descriptor lifetime')
        renames=[c for c in calls if c['name'] in ('renameat','renameat2') and c['return']==0]
        locks=[c for c in calls if c['name']=='flock']
        require(len(locks)<=1 and all(c['arguments'][1]=='LOCK_EX' for c in locks),'unchanged advisory parent lock')
        if answer['ok']:
            require(len(renames)==1 and len(locks)==1 and locks[0]['return']==0,'success actual atomic rename and advisory lock')
            rename=renames[0];sync=[c for c in calls if c['name']=='fsync']
            require(len(sync)==2 and all(c['return']==0 for c in sync) and sync[0]['line']<rename['line']<sync[1]['line'],'actual stage/data and parent fsync order')
            cleanup=[c for c in calls if c['name']=='unlinkat']
            require(len(cleanup)==1 and cleanup[0]['line']>sync[1]['line'] and cleanup[0]['errno']=='ENOENT','post-rename original temp cleanup')
            final=[c for c in calls if c['name']=='newfstatat' and c['line']>cleanup[0]['line']]
            require(len(final)==1 and final[0]['return']==0,'original final pathname verification')
            require(':'.join(map(str,final[0]['stat']['version']))==answer['version'],'actual full kernel stat binds every returned version field')
            staging=[c for c in opens if 'O_EXCL' in c['arguments'][-2 if len(c['arguments'])==4 else -1]]
            require(len(staging)==1,'one original exclusive staging FD')
            staged=staging[0];stagefd=staged['descriptor_opened']
            stageclose=[c for c in closes if c['opened_at_line']==staged['line']]
            require(len(stageclose)==1 and sync[0]['line']<stageclose[0]['line']<rename['line'],'staging fd retired before rename')
            chmod=[c for c in calls if c['name']=='fchmod']
            require(len(chmod)==1 and chmod[0]['return']==0 and fd(chmod[0]['arguments'][0])==stagefd,'real original permissions')
            written=sum(c['return'] for c in calls if c['name']=='write' and fd(c['arguments'][0])==stagefd and staged['line']<c['line']<stageclose[0]['line'] and c['return']>0)
            require(written==answer['bytes'],'all original staging bytes actually written')
            require(calls[-1]['name']=='close' and calls[-1]['return']==0,'held parent retired before original return')
        else:require(not renames,'ordinary refusal before any successful publication')
        outputs.append({'case_id':case_id,'begin_line':entry['begin']['line'],'end_line':entry['end']['line'],
            'syscall_count':len(calls),'opens':len(opens),'closes':len(closes),'successful_renames':len(renames),
            'syscalls_sha256':pin(('\n'.join(lines[c['line']-1] for c in calls)+'\n').encode())['sha256'],
            'syscalls':calls})
    return {'trace_pid':pid,'line_count':len(lines),'syscalls':total,'outside_marker_syscalls':outside,
        'marker_pairs':len(expected_ids),'operation_counts':operation_counts,'cases':outputs,
        'all_lines_consumed':True,'all_opened_descriptors_retired':True,
        'string_abbreviations_preserved':True,'complete_stat_fields_observed':True,'full_file_and_input_output_bytes_bound_separately':True}
