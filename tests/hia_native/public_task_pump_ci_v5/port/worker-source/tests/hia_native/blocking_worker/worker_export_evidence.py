"""Independent complete-byte reader for the callable worker's private borrowing."""
from __future__ import annotations
import json,re,struct
from pathlib import Path
from worker_evidence import Pool,words,sha
from worker_reference_evidence import complete_buffers,read_json
from worker_transport import decode_journal,frame

PUBLIC=['bellman_worker_init','bellman_worker_control','bellman_worker_poll','bellman_worker_receive',
        'bellman_worker_release','bellman_worker_wake_fd','bellman_worker_shutdown','bellman_worker_destroy']
BUFFER_KEYS=['before_global','after_global','before_pool','after_pool','before_output','after_output','input','after_input','before_borrow','after_borrow']

def source_evidence(root):
    proof=read_json(root/'native/bellman_worker_export_source_proof.json')
    assert proof['exports']==PUBLIC and proof['runtime_logic_images_changed'] is False and proof['native_executed'] is False
    assert proof['old_control_and_submission_and_reap_exact_after_namespace_rename'] is True
    assert proof['old_worker_and_clock_and_renderer_exact_after_namespace_rename'] is True
    for name,identity in proof['sources'].items():
        raw=(root/name).read_bytes();assert len(raw)==identity['bytes'] and sha(raw)==identity['sha256']
    mapping=proof['mapping'];assert len(set(mapping.values()))==len(mapping)
    reverse={v:k for k,v in mapping.items()};pattern=re.compile(r'\b(?:'+'|'.join(sorted(map(re.escape,reverse),key=len,reverse=True))+r')\b')
    inverse=lambda text:pattern.sub(lambda m:reverse[m.group()],text)
    old={name:(root/'tests/hia_native/blocking_worker/reference'/('standalone_'+name+'.S')).read_text() for name in ['adapter','common','run']}
    for name,raw in old.items():assert sha(raw.encode())==proof['baseline_assembly_sha256'][name]
    new={name:inverse((root/'scripts'/('bellman_worker_'+name+'.S')).read_text()) for name in ['adapter','common','run']}
    assert new['run']==old['run']
    original_control=old['adapter'][old['adapter'].index('\ncontrol:'):old['adapter'].index('\n.include "bellman_worker_common.S"')]
    actual_control=new['adapter'][new['adapter'].index('\ncontrol:'):new['adapter'].index('\n.include "bellman_worker_callable_api.S"')]
    assert original_control==actual_control
    dispatch='''write_all:
    cmp edi,1
    je queue_append
    cmp edi,2
    jne write_all_kernel
    mov rdi,[r15+G_JOURNAL_FD]
    jmp write_all_kernel

write_all_kernel:'''
    assert new['common'].count(dispatch)==1 and new['common'].replace(dispatch,'write_all:')==old['common']
    api=inverse((root/'scripts/bellman_worker_callable_api.S').read_text())
    assert api==(root/'tests/hia_native/blocking_worker/export_author/templates/api.S').read_text()
    for name,digest in proof['templates'].items():
        assert sha((root/'tests/hia_native/blocking_worker/export_author/templates'/name).read_bytes())==digest
    assert sha((root/'tests/hia_native/blocking_worker/export_author/author_export.py').read_bytes())==proof['source_author_sha256']
    return {'status':'EXACT_WORKER_GRAPH_AND_EXPORT_SOURCE_PASS','retained_worker_functions':True,'sources':proof['sources']}

def verify_export_controls(directory,component):
    capture=directory/'capture';blobs=complete_buffers(capture);calls=read_json(capture/'calls.json');report=read_json(capture/'report.json')
    receipt=read_json(directory/'processes/controls.json')
    assert receipt['started'] is True and receipt['timed_out'] is False and receipt['returncode']==0 and receipt['timeout_seconds']==60
    assert 0<=receipt['elapsed_ns']<=60000000000 and receipt['pid']==receipt['pgid'] and receipt['pid']>0
    for channel in ['stdout','stderr']:
        raw=(directory/'processes'/('controls.'+channel)).read_bytes()
        assert receipt[channel]=={'path':'processes/controls.'+channel,'bytes':len(raw),'sha256':sha(raw)}
    assert json.loads((directory/'processes/controls.stdout').read_bytes())==report
    assert report['status']=='ACTUAL_CALLABLE_EXPORT_CONTROLS_PASS' and report['executable_sha256']==component['executable_sha256']
    assert report['exports']==component['exports'] and set(report['exports'])==set(PUBLIC)
    assert report['calls']==len(calls)==161 and report['atomic_refusals']==26 and report['complete_fifo_events']==report['borrow_tokens']==41
    assert report['concurrent_host_entry_qualified'] is False and report['public_handler_qualified'] is False
    assert report['same_qualified_worker_images'] is True
    plan=[('init',0xffffffff),('init',None),('wake_fd',None),('poll',0),('receive',0),('destroy',0xfffffff8)]
    plan += [('control',0xffffffff)]*12+[('control',0)]+[('receive',0xfffffffe)]*4+[('receive',32)]
    plan += [('control',0xffffffff),('poll',0xffffffff),('receive',0xffffffff),('shutdown',0xffffffff),('destroy',0xffffffff),('wake_fd',None)]
    plan += [('release',0xffffffff)]*2+[('release',0),('release',0xffffffff),('receive',0)]
    plan += [('control',0)]*40+[('poll',1)]+[pair for _ in range(40) for pair in [('receive',32),('release',0)]]
    plan += [('receive',0),('poll',0),('shutdown',0),('poll',0),('destroy',0)]
    assert len(plan)==161
    pool=Pool();handle=None;borrow=None;sequence=0;queue=[];tags=[];pool_calls=[];previous_global=b'';stateful=False;full_bytes=0;claimed=set()
    malformed=[];valid=frame(5,1)[8:]
    malformed += [b'',valid[:7],valid[:63],valid+b'X',b'X'+valid[1:]]
    for offset,value in [(8,0),(8,8),(24,1),(32,1),(40,(1<<64)-1),(48,1),(56,1)]:
        b=bytearray(valid);struct.pack_into('<Q',b,offset,value);malformed.append(bytes(b))
    invalid_index=0;next_tag=1
    def pool_call(command):
        request=b'HBPWRQ01'+struct.pack('<7Q',command,0,0,0,0,0,0);code,out=pool.invoke(request)
        assert code==128;pool_calls.append((request,code,out));return out
    for index,(row,(name,expected)) in enumerate(zip(calls,plan)):
        assert row['index']==index and row['function']==name
        if expected is not None:assert row['result']==expected,(index,name)
        assert set(row)==set(['index','function','result','arguments']+BUFFER_KEYS+(['event'] if name=='receive' and expected==32 else []))
        b={key:blobs[row[key]] for key in BUFFER_KEYS};claimed.update(row[key] for key in BUFFER_KEYS);full_bytes+=sum(map(len,b.values()))
        assert b['input']==b['after_input']
        assert b['before_global']==previous_global
        assert b['before_pool']==(pool.complete_state() if stateful else b'')
        args=row['arguments'];assert len(args)=={'init':1,'control':3,'poll':1,'receive':3,'release':2,'wake_fd':1,'shutdown':1,'destroy':1}[name]
        if name!='init':assert args[0]==handle
        if row['result'] in [0xffffffff,0xfffffffe,0xfffffff8,0xfffffff9]:
            for left,right in [('before_global','after_global'),('before_pool','after_pool'),('before_output','after_output'),('before_borrow','after_borrow')]:assert b[left]==b[right]
        if borrow is None:assert b['before_borrow']==b''
        else:assert b['before_borrow']==b['after_borrow']==borrow['bytes']
        if name=='init':
            if expected==0xffffffff:assert args==[1] and b['after_global']==b''
            else:
                assert args==[2] and type(row['result']) is int and row['result']>0xffffffff
                handle=row['result'];pool_call(0);stateful=True
        elif name=='control':
            assert len(b['input'])==args[2]+1 and b['input'][-1:]==b'\0'
            wire=b['input'][:-1]
            if expected==0xffffffff and invalid_index<12:
                assert wire==malformed[invalid_index];invalid_index+=1
            elif expected==0xffffffff:
                assert wire==frame(5,2)[8:] and borrow is not None
            else:
                assert wire==frame(5,next_tag)[8:];out=pool_call(10)
                event=b'HBPMSR01'+struct.pack('<7Q',192,1,next_tag,0,128,0,0)+out
                queue.append(event);next_tag+=1
        elif name=='receive':
            assert b['before_output']==bytes([0xa5])*40
            if expected==32:
                assert borrow is None and queue
                actual=blobs[row['event']];claimed.add(row['event']);full_bytes+=len(actual)
                assert actual==queue[0]
                assert b['after_output'][:8]==b'HBWBRW01' and b['after_output'][32:]==bytes([0xa5])*8
                ptr,size,token=struct.unpack_from('<3Q',b['after_output'],8)
                g=b['after_global'];base=struct.unpack_from('<Q',g,160)[0];cursor=struct.unpack_from('<Q',g,184)[0]
                assert ptr==base+cursor+8 and size==len(actual) and token==sequence+1
                sequence=token;borrow={'bytes':actual,'token':token};tags.append(words(actual[:64])[3])
            else:assert b['after_output']==b['before_output']
            if expected==0:assert not queue and borrow is None
            if expected==0xfffffffe:assert args[2] in [0,1,7,31]
        elif name=='release':
            if expected==0:
                assert borrow is not None and args[1]==borrow['token'];queue.pop(0);borrow=None
            else:assert borrow is None or args[1]!=borrow['token']
        elif name=='poll' and expected in [0,1]:assert bool(queue)==bool(expected)
        elif name=='shutdown' and expected==0:pool_call(9)
        elif name=='destroy' and expected==0:
            assert borrow is None and not queue;pool_call(10);stateful=False
        elif name=='wake_fd':
            assert row['result']==struct.unpack_from('<Q',b['after_global'],48)[0] and 3<=row['result']<1<<31
        assert b['after_pool']==(pool.complete_state() if stateful else b'')
        if stateful:
            g=b['after_global'];assert len(g)==4096 and g[232:240]==b'HBWXST01' and g[224:232]==bytes(8)
            assert struct.unpack_from('<Q',g,32)[0]==receipt['pid'] and struct.unpack_from('<Q',g,216)[0]==2
            assert struct.unpack_from('<Q',g,24)[0]==0
            assert struct.unpack_from('<Q',g,192)[0]==sequence
            assert struct.unpack_from('<Q',g,200)[0]==(borrow['token'] if borrow else 0)
            assert struct.unpack_from('<Q',g,208)[0]==(len(borrow['bytes']) if borrow else 0)
            assert struct.unpack_from('<Q',g,152)[0]==len(pool_calls)
        else:assert b['after_global']==b''
        previous_global=b['after_global']
    assert tags==list(range(1,42)) and next_tag==42 and invalid_index==12 and not queue and borrow is None
    assert claimed==set(blobs) and full_bytes==report['complete_buffer_bytes']
    journals=decode_journal((directory/'processes/controls.stderr').read_bytes())
    assert len(journals)==len(pool_calls)+1==45
    for index,((magic,raw),(request,code,out)) in enumerate(zip(journals,pool_calls),1):
        assert magic==b'HBWPL001' and words(raw[:32])[2:]==[receipt['pid'],words(request)[1]]
        assert raw[32:96]==request and words(raw[96:112])==[code,index] and raw[112:240]==out and raw[240:]==bytes(16)
    magic,final=journals[-1];assert magic==b'HBWPEND1'
    assert words(final[:64])[1:]==[4160,4096,receipt['pid'],44,0,0,0] and final[64:]==pool.complete_state()
    return {'status':'READ_ONLY_EXPORT_CONTROLS_PASS','calls':161,'atomic_refusals':26,'complete_fifo_events':41,
            'complete_buffer_bytes':full_bytes,'actual_pool_calls':44,'native_or_rust_executed':False}
