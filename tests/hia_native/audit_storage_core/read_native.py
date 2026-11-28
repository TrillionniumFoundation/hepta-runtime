"""Read complete native input/output/workspace observations without executing either owner."""
from pathlib import Path
import gzip
import struct
from common import loads,pin,read,require
from protocol import (INVALID,CAPACITY,cases,initial,response,semantic,word,put,acknowledgement)
from abi_controls import initial_controls,acknowledgement_controls

class Calls:
    def __init__(self,folder):
        self.rows=loads(read(folder/'INVOCATIONS.json'))
        self.index=0;self.logical_bytes=0
        self.file=gzip.GzipFile(fileobj=(folder/'buffers.bin.gz').open('rb'),mode='rb')
        require(self.file.read(8)==b'AIOLOG01','complete physical journal header')
    def exact(self,n):
        raw=self.file.read(n);require(len(raw)==n,'complete physical buffer extent')
        self.logical_bytes+=n;return raw
    def call(self,module,wire,out_size,work,case,step,probe=None):
        require(self.index<len(self.rows),'every actual call present')
        require(self.exact(8)==b'AIOCAL01','actual invocation marker')
        fields=struct.unpack('<9Q',self.exact(72))
        index,ci,si,mod,result,ni,no,nw,isp=fields
        require((index,ci,si,mod,ni,no,nw,isp)==
                (self.index,case,step,module,len(wire),out_size,len(work),int(probe is not None)),
                'exact source-owned ordered call identity')
        before=[self.exact(n+16) for n in (ni,no,nw)]
        after=[self.exact(n+16) for n in (ni,no,nw)]
        require(before==[wire+b'\xc3'*16,b'\xa5'*(no+16),work+b'\x5a'*16],
                'actual complete native input and buffer preimages')
        require(after[0]==before[0] and after[1][no:]==b'\xa5'*16 and after[2][nw:]==b'\x5a'*16,
                'every actual input byte and both borrowed guards')
        row=self.rows[index]
        require(row==dict(index=index,case=case,step=step,module=module,result=result,probe=probe,
            input_bytes=ni,output_capacity=no,workspace_capacity=nw,elapsed_ns=row['elapsed_ns'],
            before=[pin(v) for v in before],after=[pin(v) for v in after])
            and type(row['elapsed_ns']) is int and row['elapsed_ns']>=0,
            'every full buffer pin and call receipt')
        if probe is not None:
            require(result==probe['expected'] and after[1:]==before[1:],
                    'actual full-buffer rejection atomicity')
        elif result in (INVALID,CAPACITY):
            require(module==1 and result==INVALID and after[1]==before[1],
                    'only actual typed JSON rejection may return INVALID')
        else:
            require(result<=no and after[1][result:no]==b'\xa5'*(no-result),
                    'complete produced output and untouched unused tail')
        self.index+=1
        return result,after[1][:no],after[2][:nw],index
    def probes(self,rows,workspace,case,step,prefix):
        for name,wire,out_size,work_size,writes,expected in rows:
            work=bytearray((workspace+b'\x79'*max(0,work_size-len(workspace)))[:work_size])
            for at,value in writes:put(work,at,value)
            self.call(0,wire,out_size,bytes(work),case,step,
                dict(name=prefix+'/'+name,expected=expected,writes=[list(x) for x in writes]))
    def finish(self):
        require(self.exact(8)==b'AIOEND01' and struct.unpack('<Q',self.exact(8))[0]==self.index
                and self.index==len(self.rows) and not self.file.read(1),'all native calls and closed gzip/footer')
        self.file.close()
        return dict(calls=self.index,logical_buffer_bytes=self.logical_bytes)

def filesystem_reply(state,row,capabilities):
    require('kind' not in row and row['generation']==state['generation']
        and row['sequence']==state['sequence'] and row['operation']==state['operation']
        and row['arguments']==list(state['arguments'])
        and row['payloads']==[x.hex() for x in state['payloads']]
        and row['capabilities_before']==capabilities,'complete owned syscall request')
    actual=row['observed'];ret=actual['actual_return'];errno=actual['actual_errno']
    require(type(ret) is int and type(errno) is int and 0<=errno<=4095,'actual libc result and errno')
    op=state['operation'];a,b,c=state['arguments'];status=0;value=0;payload=b''
    after=dict(capabilities)
    if ret<0 and op!=13:
        require(ret==-1 and errno>0,'actual OS error result')
        status=1
    elif op in (1,11,12):
        require(ret>=0 and (op!=12 or ret>0),'actual new descriptor')
        ack=bytes.fromhex(row['acknowledgement_hex']);value=word(ack,56)
        require(value>1 and str(value) not in capabilities,'fresh opaque descriptor')
        if op==12:
            require(after.pop(str(a),None)=='file','consumed duplicate FD')
        after[str(value)]='directory' if op==12 else 'file'
    elif op==2:
        raw=bytes.fromhex(actual['complete_linux_x86_64_stat_hex'])
        require(ret==0 and len(raw)==144,'complete actual Linux stat')
        dev,ino,nlink=struct.unpack_from('<3Q',raw)
        mode,uid=struct.unpack_from('<2I',raw,24)
        size=struct.unpack_from('<q',raw,48)[0]
        require(size>=0,'actual stat file extent')
        payload=struct.pack('<8Q',mode,uid,nlink,size,dev,ino,0,0)
    elif op==3:
        require(ret<=0xffffffff,'actual effective uid width');value=ret
    elif op==4:
        ack=bytes.fromhex(row['acknowledgement_hex']);payload=ack[128:];value=ret
        require(ret==len(payload)<=b,'actual read complete bytes and count')
    elif op==5:
        require(ret<=b==len(state['payloads'][0]),'actual write count');value=ret
    elif op==13:
        require(actual['readdir_nonnull'] is bool(ret),'actual null/nonnull readdir boundary')
        if ret:
            raw=bytes.fromhex(actual['complete_linux_dirent_hex'])
            require(20<=len(raw)<=8192 and struct.unpack_from('<H',raw,16)[0]==len(raw),
                    'complete actual dirent bytes')
            end=raw.find(b'\0',19);require(end>=19,'actual dirent terminator')
            payload=raw[:8]+raw[19:end];value=1
    else:
        require(ret==0,'actual completed syscall return')
    if op in (7,14):
        require(a!=1 and after.pop(str(a),None)==('directory' if op==14 else 'file'),
                'all owned closes remove the exact capability')
    if status==0 and op not in (7,13):errno=0
    ack=acknowledgement(state,status=status,errno=errno,value=value,payload=payload)
    require(ack.hex()==row['acknowledgement_hex'] and after==row['capabilities_after'],
            'complete syscall result projection and capability conservation')
    return ack,after

def verify(folder,domain):
    report=loads(read(folder/'NATIVE.json'))
    observations=loads(read(folder/'OBSERVATIONS.json'))
    events=[loads(line) for line in read(folder/'effects.jsonl').splitlines()]
    require(report['status']=='PASS' and report['cases']==219 and report['operations']==459
            and len(observations)==459,'entire frozen native filesystem corpus')
    calls=Calls(folder);event_index=0;obs_index=0;seen=set();names=[];operations=set()
    wire=initial(0,0,domain[0]['steps'][0])
    calls.probes(initial_controls(wire,8192,32768),bytes(32768),0,0,'initial')
    for ci,case in enumerate(domain):
        work=bytes(32768);caps={'1':'file'}
        for si,step in enumerate(case['steps']):
            wire=initial(ci,si,step);turn=wire;first=calls.index;sequence=0
            while True:
                returned,out,work,index=calls.call(0,turn,8192,work,ci,si)
                require(128<=returned<=8192,'complete actual owner frame')
                state=response(out[:returned],returned)
                require(state['generation']==word(wire,16),'same source-owned generation')
                if state['kind'] in (0,1):
                    require(caps=={'1':'file'} and state['sequence']==sequence,'terminal resources and effect sequence')
                    observed=observations[obs_index];obs_index+=1
                    require(observed['case']==ci and observed['step']==si and observed['initial_hex']==wire.hex()
                        and observed['first_call']==first and observed['last_call']==index
                        and observed['semantic_hex']==semantic(out[:returned]).hex(),'native complete terminal projection')
                    if 'terminal-ack' not in seen and turn[:8]==b'HAIOACK1':
                        calls.call(0,turn,8192,work,ci,si,
                            dict(name='terminal-ack-replay',expected=INVALID,writes=[]))
                        seen.add('terminal-ack')
                    break
                sequence+=1
                require(state['sequence']==sequence and event_index<len(events),'all actual effects exactly once')
                row=events[event_index];event_index+=1
                require(row['case']==ci and row['step']==si,'same owned operation effect')
                if state['kind']==2:
                    turn,caps=filesystem_reply(state,row,caps)
                else:
                    returned,child_out,_,child_index=calls.call(1,state['payloads'][0],4096,bytes(8192),ci,si)
                    require(returned==INVALID or returned<=4096,'frozen JSON result')
                    turn=acknowledgement(state,status=2 if returned==INVALID else 0,value=returned,
                                        payload=b'' if returned==INVALID else child_out[:returned])
                    require(row==dict(case=ci,step=si,generation=state['generation'],sequence=sequence,
                        operation=state['operation'],kind=3,child_call=child_index,
                        input_hex=state['payloads'][0].hex(),acknowledgement_hex=turn.hex()),
                        'complete actual shared JSON child frame and return')
                key=(state['kind'],state['operation'],word(turn,40));operations.add(key[:2])
                if key not in seen:
                    calls.probes(acknowledgement_controls(turn,8192,len(work)),work,ci,si,
                                 'ack-%d-%d-%d'%key);seen.add(key)
    require(event_index==len(events) and obs_index==len(observations),'no missing or surplus native effects/results')
    require(operations=={(2,i) for i in range(1,15)}|{(3,1),(3,3)},'all installed actual filesystem and codec effects')
    summary=calls.finish()
    require(report['native_calls']==summary['calls'] and report['json_calls']==sum(r['module']==1 for r in calls.rows)
        and report['controls']==[r['probe']['name'] for r in calls.rows if r['probe'] is not None],
        'entire actual protocol control inventory')
    for name,path in (('buffers','buffers.bin.gz'),('invocations','INVOCATIONS.json'),('effects','effects.jsonl'),
                      ('observations','OBSERVATIONS.json'),('retirement','RETIREMENT.json')):
        require(report[name]==pin(read(folder/path)),'complete native report physical file identity')
    return dict(**summary,effects=len(events),json_calls=report['json_calls'],
                refusals=len(report['controls']),observations=observations,events=events)
