"""Exact retained syscall parser; only the two native marker spellings differ."""
from read_original import LINE, CALL, ERRORS, strings
from common import require

def native_trace(raw,pid,domain):
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
                if row.startswith(b'AUDIT_PUMP_BEGIN '):
                    ci,gen=map(int,row.split()[1:])
                    require(current is None and (ci,gen) not in result,'unique actual original begin')
                    current=(ci,gen);result[current]=[];order.append(current)
                elif row.startswith(b'AUDIT_PUMP_END '):
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
