"""Compare complete original frames/files and the actual durable syscall order."""
from pathlib import Path
import errno
import re
import stat
import struct
from common import ROOT,encoded,loads,pin,read,require
from protocol import cases,initial,word,validate_semantic
from fixture import normalized

HEX=re.compile(r'"((?:\\x[0-9a-f]{2})*)"')
LINE=re.compile(r'^([0-9]+)\s+(.*)$')
CALL=re.compile(r'^([a-z0-9_]+)\((.*)\)\s+=\s+(-?[0-9]+)(?:\s+([A-Z][A-Z0-9_]+))?')
ERRORS={name:number for number,name in errno.errorcode.items()}

def strings(text):
    return [bytes.fromhex(value.replace('\\x','')) for value in HEX.findall(text)]

def initial_files(case,rows,uid,gid):
    actual=normalized(rows)
    require(actual and actual[0]['path_hex']=='' and actual[0]['kind']=='directory'
        and actual[0]['mode']==stat.S_IFDIR|case['root_mode']
        and actual[0]['uid']==uid and actual[0]['gid']==gid,'complete initial owned directory')
    entries={x['name_hex']:x for x in case['entries']}
    require({r['path_hex'] for r in actual[1:]}==set(entries),'every initial fixture path exactly once')
    by_name={r['path_hex']:r for r in actual[1:]}
    groups={}
    for name,entry in entries.items():
        target=entry['target_hex'] if entry['kind']=='hardlink' else name
        groups.setdefault(target,[]).append(name)
    require(actual[0]['nlink']==2+sum(e['kind']=='directory' for e in entries.values()),
            'source-owned initial directory link count')
    for name,entry in entries.items():
        row=by_name[name]
        if entry['kind']=='hardlink':entry=entries[entry['target_hex']]
        require(row['uid']==uid and row['gid']==gid,'source-owned fixture uid/gid')
        if entry['kind']=='file':
            target=next(key for key,members in groups.items() if name in members)
            require(row['kind']=='file' and row['mode']==stat.S_IFREG|entry['mode']
                and row['data_hex']==entry['data_hex'] and row['nlink']==len(groups[target])
                and row['hardlinks']==sorted(groups[target]),'complete initial file bytes and hardlink binding')
        elif entry['kind']=='directory':
            require(row['kind']=='directory' and row['mode']==stat.S_IFDIR|entry['mode']
                    and row['nlink']==2,'initial ordinary directory')
        elif entry['kind']=='fifo':
            require(row['kind']=='fifo' and row['mode']==stat.S_IFIFO|entry['mode']
                    and row['nlink']==1,'initial FIFO observed without opening')
        elif entry['kind']=='symlink':
            require(row['kind']=='symlink' and row['mode']==stat.S_IFLNK|0o777
                    and row['nlink']==1 and row['target_hex']==entry['target_hex'],'complete initial symlink text')

def original_trace(raw,pid,domain):
    current=None;buffer=b'';stderr=b'';fd={};result={};order=[]
    for line in raw.decode('utf-8').splitlines():
        match=LINE.match(line)
        require(match is not None,'complete strace line with actual pid')
        if int(match[1])!=pid:continue
        text=match[2];call=CALL.match(text)
        if call is None:
            # The full trace retains stdin wait/resume and process notices.
            require('<unfinished ...>' in text or text.startswith('<... ') or text.startswith('--- ')
                    or text.startswith('+++ '),'understood complete strace record')
            continue
        op,args,ret,error=call.groups();ret=int(ret)
        code=0 if ret>=0 else ERRORS.get(error)
        require(code is not None,'exact observed original OS errno')
        payloads=strings(args)
        if op=='openat' and ret>=0:
            require(payloads,'complete original open component')
            name=payloads[0]
            fd[ret]='directory' if name==b'.' or name.rsplit(b'/',1)[-1].startswith(b'case-') else 'file'
        if op in ('write','writev') and args.startswith('2, '):
            raw=b''.join(payloads)
            require(payloads and ret==len(raw),'complete original stderr marker write')
            buffer+=raw;stderr+=raw
            while b'\n' in buffer:
                row,buffer=buffer.split(b'\n',1)
                if row.startswith(b'AUDIT_ORIGINAL_BEGIN '):
                    ci,gen=map(int,row.split()[1:])
                    require(current is None and (ci,gen) not in result,'unique actual original begin')
                    current=(ci,gen);result[current]=[];order.append(current)
                elif row.startswith(b'AUDIT_ORIGINAL_END '):
                    ci,gen=map(int,row.split()[1:])
                    require(current==(ci,gen),'actual original end after same begin')
                    current=None
                else:
                    require(current is not None and row.startswith(b'OBSERVED_ORIGINAL_ERROR '),
                            'complete actual original diagnostic record')
            continue
        if current is not None and op in ('write','fsync','linkat','unlinkat','renameat'):
            if op=='write':
                number=int(args.split(',',1)[0])
                if number not in (0,1,2):
                    require(len(payloads)==1,'complete original written bytes')
                    result[current].append(dict(operation=5,payloads=[payloads[0].hex(), ''],
                                                return_value=ret,errno=code))
            elif op=='fsync':
                number=int(args)
                require(number in fd,'known original fsync descriptor')
                result[current].append(dict(operation=6,directory=fd[number]=='directory',
                                            return_value=ret,errno=code))
            else:
                expected=1 if op=='unlinkat' else 2
                require(len(payloads)==expected,'complete original publication paths')
                result[current].append(dict(operation={'linkat':8,'unlinkat':9,'renameat':10}[op],
                    payloads=[payloads[0].hex(),'' if expected==1 else payloads[1].hex()],
                    return_value=ret,errno=code))
        if op=='close' and ret==0:fd.pop(int(args),None)
    expected=[(i,1+i*100+j) for i,c in enumerate(domain) for j in range(len(c['steps']))]
    require(current is None and not buffer and order==expected,'every original operation bounded by actual markers')
    return result,stderr

def verify(root,metadata,native):
    domain=cases(ROOT);folder=root/'original'
    report=loads(read(folder/'ORIGINAL.json'));process=loads(read(folder/'process.json'))
    observations=loads(read(folder/'OBSERVATIONS.json'))
    require(report['status']=='PASS' and report['cases']==219 and report['operations']==459
        and len(observations)==459 and process['success'] is True and process['exit_code']==0
        and type(process['pid']) is int and process['pid']>1 and process['parent_pid']!=process['pid']
        and process['pgid']!=process['pid'] and process['pgid']>1
        and process['timeout_seconds']==60 and 0<=process['elapsed_seconds']<=60
        and process['owned_root']==metadata['owned_fixture'] and process['source_root']==metadata['source_root']
        and process['argv']==[str(Path(metadata['producer_root'])/'original.elf'),metadata['owned_fixture']]
        and process['trace_environment_absent'] is True
        and process['binary']==metadata['original_binary'],'actual fresh original process and same absolute fixture path')
    for kind in ('stdin','stdout','stderr'):
        require(pin(read(folder/('original.'+kind)))==process[kind],'complete original process stream')
    stdin=b''.join(struct.pack('<2Q',i,len(w))+w for i,c in enumerate(domain)
        for j,step in enumerate(c['steps']) for w in [initial(i,j,step)])
    require(read(folder/'original.stdin')==stdin,'every exact original input frame')
    stdout=b'';index=0;errors=[];expected_error_generations=[]
    for ci,case in enumerate(domain):
        previous=None
        for si,step in enumerate(case['steps']):
            row=observations[index];other=native['observations'][index];index+=1
            wire=initial(ci,si,step)
            require(row['case']==ci and row['step']==si and row['initial_hex']==wire.hex()
                and row['semantic_hex']==other['semantic_hex'],'complete original and HIA terminal bytes')
            raw=validate_semantic(bytes.fromhex(row['semantic_hex']))
            stdout+=struct.pack('<Q',len(raw))+raw
            if word(raw,8)==1:expected_error_generations.append(word(wire,16))
            for when in ('before','after'):
                require(normalized(row[when])==normalized(other[when]),'complete original/HIA filesystem '+when)
            if previous is None:
                initial_files(case,row['before'],metadata['uid'],metadata['gid'])
                initial_files(case,other['before'],metadata['uid'],metadata['gid'])
            else:
                require(normalized(previous)==normalized(row['before']),'persistent same-case filesystem state')
            previous=row['after']
    require(read(folder/'original.stdout')==stdout,'all original complete framed stdout bytes')
    expected_lines=[]
    actual_lines=read(folder/'original.stderr').splitlines()
    cursor=0;error_count=0
    for ci,case in enumerate(domain):
        for si,step in enumerate(case['steps']):
            gen=1+ci*100+si
            require(actual_lines[cursor]==('AUDIT_ORIGINAL_BEGIN %d %d'%(ci,gen)).encode(),'complete original begin stderr')
            cursor+=1
            if gen in expected_error_generations:
                prefix=b'OBSERVED_ORIGINAL_ERROR '
                require(actual_lines[cursor].startswith(prefix),'complete original error text retained')
                error=loads(actual_lines[cursor][len(prefix):]);cursor+=1;error_count+=1
                require(error['generation']==gen and type(error['display']) is str
                    and type(error['debug']) is str and type(error['chain']) is list
                    and error['chain'] and error['chain'][0]==error['display'],'complete original error chain')
            require(actual_lines[cursor]==('AUDIT_ORIGINAL_END %d %d'%(ci,gen)).encode(),'complete original end stderr')
            cursor+=1
    require(cursor==len(actual_lines),'no unbound original stderr bytes')
    traced,traced_stderr=original_trace(read(root/'original.strace'),process['pid'],domain)
    require(traced_stderr==read(folder/'original.stderr'),'complete stderr equals independently retained real syscall bytes')
    actual={key:[] for key in traced}
    for event in native['events']:
        if event.get('kind')==3:continue
        key=(event['case'],event['generation']);op=event['operation'];r=event['observed']
        if op not in (5,6,8,9,10):continue
        base=dict(operation=op,return_value=r['actual_return'],
                  errno=r['actual_errno'] if r['actual_return']<0 else 0)
        if op==6:base['directory']=event['arguments'][0]==1
        else:base['payloads']=event['payloads']
        actual[key].append(base)
    require(actual==traced,'every actual durable write/sync/link/unlink/rename result in original order')
    for label in ('native','original'):
        retirement=loads(read(root/label/'RETIREMENT.json'))
        require(retirement['owned_root']==metadata['owned_fixture'] and retirement['removed_after_capture'] is True
                and len(retirement['complete_final_observations'])==219,'complete owned fixture retirement observations')
        rows=native['observations'] if label=='native' else observations
        final={r['case']:r['after'] for r in rows}
        require(all(normalized(retirement['complete_final_observations'][i])==normalized(final[i]) for i in range(219)),
                'every retired fixture retains its complete final filesystem')
    for key,path in (('process','process.json'),('observations','OBSERVATIONS.json'),('retirement','RETIREMENT.json')):
        require(report[key]==pin(read(folder/path)),'original report exact file identity')
    return dict(cases=219,operations=459,original_errors=error_count,
                complete_stdout=pin(stdout),durable_syscalls=sum(map(len,actual.values())),
                full_actual_strace=pin(read(root/'original.strace')),filesystem_equal=True)
