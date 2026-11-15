"""Deterministic external-writer interleavings at actual completed effects.

The static ELF performs real effects and waits for a fixed identity-only ACK.
The observer changes real owned files; no effect result is supplied by Python.
"""
from __future__ import annotations
import argparse,json,os,selectors,struct,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from hia_native_text_publication_fixtures import (
    b64,unb64,data,materialize,node,file_node,case,digest,setup_fixture,request_bytes,
    snapshot,save_json,version,expected_output,EXISTING_LIMIT,
)
from qualify_hia_text_publication_native import StreamProcess,require,file_pin,receipt_records

def race_cases():
    rows=[]
    def add(name,trigger,action,*,mode=2,setup=None,error=None,published=False,
            actual=None,target=b'target',path=b'/target',after_target=None):
        row=case(name,mode=mode,content=b'new\n',setup=[file_node(b'old\n')] if setup is None else setup,
                 path=path,target=target,error=error,domain='races')
        row['race']={'trigger':trigger,'action':action,'published':published,
                     'actual_data':None if actual is None else data(actual),
                     'after_target_base64':b64(target if after_target is None else after_target)}
        rows.append(row)
    first_stat={'kind':7,'args_prefix':[3,768]}
    stage_close={'kind':3,'args_prefix':[4]}
    rename={'kind':17}
    no_entry='No such file or directory (os error 2)'
    add('grow-during-read',first_stat,{'op':'append','data':data(b'x')},error=15)
    add('shrink-during-read',{'kind':10,'args_prefix':[3]}, {'op':'truncate','size':1},
        setup=[file_node(b'x',size=65537)],error=15)
    add('grow-past-reader-limit',first_stat,{'op':'append','data':data(b'x')},
        setup=[file_node(b'a',size=EXISTING_LIMIT)],error=14)
    add('replace-open-path',{'kind':6},{'op':'replace','data':data(b'rival')},error=5)
    add('unlink-open-path',{'kind':6},{'op':'unlink'},error=5)
    add('replace-after-final-source-stat',{'kind':7,'args_prefix':[3,912]},
        {'op':'replace','data':data(b'rival')},error=22)
    add('unlink-after-final-source-stat',{'kind':7,'args_prefix':[3,912]},
        {'op':'unlink'},error=no_entry)
    add('replace-before-publish',stage_close,{'op':'replace','data':data(b'rival')},error=22)
    add('unlink-before-publish',stage_close,{'op':'unlink'},error=no_entry)
    add('chmod-before-publish',stage_close,{'op':'chmod_and_mtime','mode':0o400},error=22)
    add('competing-create-after-random',{'kind':12},{'op':'create','data':data(b'rival')},
        mode=1,setup=[],error=23)
    add('competing-create-before-probe',{'kind':4},{'op':'create','data':data(b'rival')},
        mode=1,setup=[],error=10)
    add('replace-after-final-source-check',{'kind':5,'args_prefix':[],'arg_equals':{'3':912}},
        {'op':'replace','data':data(b'rival')},published=True,actual=b'new\n')
    add('unlink-after-rename',rename,{'op':'unlink'},error=no_entry,published=True)
    add('same-inode-same-size-overwrite-after-rename',rename,{'op':'overwrite','data':data(b'evil')},
        published=True,actual=b'evil')
    add('shrink-after-rename',rename,{'op':'truncate','size':1},error=25,published=True)
    add('extend-after-rename',rename,{'op':'append','data':data(b'external')},error=25,published=True)
    add('replace-inode-after-rename',rename,{'op':'replace','data':data(b'new\n')},error=25,published=True)
    add('symlink-after-rename',rename,{'op':'symlink','target_base64':b64(b'other')},
        setup=[file_node(b'old\n'),file_node(b'other',path=b'other')],error=25,published=True)
    add('held-parent-directory-renamed',{'kind':4},
        {'op':'rename_parent','from_base64':b64(b'inner'),'to_base64':b64(b'moved')},
        mode=1,setup=[node('directory',b'inner')],target=b'inner/target',path=b'/inner/target',
        after_target=b'moved/target',published=True,actual=b'new\n')
    return rows

def parse_receipt(frame):
    require(len(frame)==256 and frame[:8]==b'HTXTEF01','fixed sync receipt')
    generation,sequence,kind,phase,raw_return,workcap,reserved=struct.unpack_from('<7Q',frame,8)
    fields=struct.unpack_from('<16Q',frame,64)
    require(frame[64:72]==b'HTXTFX01' and fields[1:4]==(sequence,generation,kind),'sync receipt identity')
    require(fields[13]==1 and fields[12]==fields[14]==fields[15]==reserved==0,'completed effect before ACK')
    return {'generation':generation,'sequence':sequence,'kind':kind,'phase':phase,
            'args':list(fields[4:10]),'value':fields[10],'errno':fields[11],
            'raw_return':raw_return,'workspace_capacity':workcap}

class Actor:
    def __init__(self,description,fixture,root,blobs):
        self.description=description;self.fixture=Path(fixture);self.root=Path(root);self.blobs=blobs
        self.fired=False;self.record=None
    def __call__(self,receipt):
        trigger=self.description['race']['trigger']
        if self.fired or receipt['kind']!=trigger['kind'] or receipt['errno']!=0:return
        prefix=trigger.get('args_prefix',[])
        if receipt['args'][:len(prefix)]!=prefix:return
        if any(receipt['args'][int(i)]!=v for i,v in trigger.get('arg_equals',{}).items()):return
        self.fired=True;action=self.description['race']['action'];operation=action['op']
        target=os.fsencode(self.fixture)+b'/'+unb64(self.description['expect']['target_base64'])
        before=snapshot(self.fixture,self.blobs);start=time.monotonic_ns()
        if operation=='append':
            with open(target,'ab',buffering=0) as stream:stream.write(materialize(action['data']))
        elif operation=='truncate':os.truncate(target,action['size'])
        elif operation=='unlink':os.unlink(target)
        elif operation in ('replace','create'):
            name=target+b'.actor-new' if operation=='replace' else target
            with open(name,'xb',buffering=0) as stream:stream.write(materialize(action['data']))
            os.chmod(name,0o600)
            if operation=='replace':os.replace(name,target)
        elif operation=='overwrite':
            raw=materialize(action['data']);before_stat=os.lstat(target)
            require(len(raw)==before_stat.st_size,'same-size actor input')
            with open(target,'r+b',buffering=0) as stream:
                require(stream.write(raw)==len(raw),'complete in-place external write')
            after_stat=os.lstat(target)
            require((before_stat.st_dev,before_stat.st_ino,before_stat.st_size)==
                    (after_stat.st_dev,after_stat.st_ino,after_stat.st_size),'same actual inode and size after actor')
        elif operation=='chmod_and_mtime':
            before_stat=os.lstat(target);os.chmod(target,action['mode'])
            os.utime(target,ns=(before_stat.st_atime_ns,before_stat.st_mtime_ns-2000000000))
        elif operation=='symlink':
            name=target+b'.actor-link';os.symlink(unb64(action['target_base64']),name);os.replace(name,target)
        elif operation=='rename_parent':
            os.rename(os.fsencode(self.fixture)+b'/'+unb64(action['from_base64']),
                      os.fsencode(self.fixture)+b'/'+unb64(action['to_base64']))
        else:raise ValueError('unknown explicit actor operation')
        end=time.monotonic_ns();after=snapshot(self.fixture,self.blobs)
        self.record={'trigger_receipt':receipt,'operation':action,'monotonic_start_ns':start,
                     'monotonic_end_ns':end,'before':before,'after':after,'effect_results_injected':False}
        save_json(self.root/'actor.json',self.record)

class SyncProcess(StreamProcess):
    def __init__(self,elf,root):
        super().__init__(elf,root,flags=('--sync',));self.receipt_buffer=bytearray()
    def exchange(self,wire,kind,actor=None):
        started=time.monotonic();deadline=started+60;before=dict(self.counts)
        queue=bytearray(struct.pack('<Q',len(wire))+wire);at=0;size=None;receipts=0
        self.selector.register(self.proc.stdin,selectors.EVENT_WRITE,'stdin')
        while True:
            remaining=deadline-time.monotonic();require(remaining>0,'unchanged sync 60-second exchange deadline')
            for key,_ in self.selector.select(min(remaining,0.25)):
                if key.data=='stdin':
                    count=os.write(key.fd,queue[at:at+65536]);require(count>0,'sync stdin progress')
                    self.capture('stdin',queue[at:at+count]);at+=count
                    if at==len(queue):self.selector.unregister(self.proc.stdin)
                    continue
                if key.data=='stdout':self.read_event(key);continue
                raw=os.read(key.fd,65536)
                if not raw:self.selector.unregister(key.fileobj);continue
                self.capture('stderr',raw);self.receipt_buffer.extend(raw)
                while len(self.receipt_buffer)>=256:
                    frame=bytes(self.receipt_buffer[:256]);del self.receipt_buffer[:256]
                    receipt=parse_receipt(frame);receipts+=1
                    if actor is not None:actor(receipt)
                    ack=b'HTXTACK1'+struct.pack('<2Q',receipt['generation'],receipt['sequence'])
                    queue.extend(ack)
                    try:self.selector.get_key(self.proc.stdin)
                    except KeyError:self.selector.register(self.proc.stdin,selectors.EVENT_WRITE,'stdin')
            if len(self.buffer)>=8 and size is None:
                size=struct.unpack_from('<Q',self.buffer)[0];require(64<=size<=1024,'fixed sync response extent')
            if size is not None and len(self.buffer)>=size+8:
                require(len(self.buffer)==size+8 and at==len(queue) and not self.receipt_buffer,'complete ACK and result boundary')
                record=bytes(self.buffer[8:]);self.buffer.clear();break
            require(not self.stdout_eof,'sync stdout ended before response')
        require(record[:8]==b'HTXTER01','sync response magic')
        code,generation,sequence,payload_len,live,phase,reserved=struct.unpack_from('<7Q',record,8)
        require(reserved==0 and code<1<<32 and payload_len==len(record)-64 and live==0,'sync terminal envelope')
        exchange={'kind':kind,'started_stream_offsets':before,'ended_stream_offsets':dict(self.counts),
                  'request_bytes':len(wire),'request_sha256':digest(wire),'record_bytes':len(record),
                  'record_sha256':digest(record),'elapsed_seconds':time.monotonic()-started,'timeout_seconds':60,
                  'effect_receipts':receipts,'identity_only_acknowledgements':receipts}
        self.exchanges.append(exchange)
        return {'code':code,'generation':generation,'sequence':sequence,'phase':phase,
                'live_fds':live,'payload':record[64:],'record':record,'exchange':exchange}

def stable_nodes(rows):
    return [row for row in rows if row['kind']!='directory' and
            not unb64(row['path_base64']).split(b'/')[-1].startswith(b'.hepta-text-')]

def verify_result(description,result,actor,after,blobs,diagnostics,fixture):
    require(actor.fired and actor.record is not None,'the actual requested effect triggered its external actor')
    body=result['payload'];require(result['code']==len(body) and result['phase']==100,'race terminal HIA result')
    require(body[:8]==b'HTXTR001','race result body magic')
    tag,error_len,size,was_new,generation,sequence,reserved=struct.unpack_from('<7Q',body,8)
    require(reserved==0 and (generation,sequence)==(result['generation'],result['sequence']),'race lifecycle identity')
    require(all(not unb64(row['path_base64']).split(b'/')[-1].startswith(b'.hepta-text-') for row in after),'all temporary publication names cleaned')
    if description['expect']['kind']=='error':
        error=description['expect']['error'];message=diagnostics[error] if type(error) is int else error
        require(tag==1 and error_len==len(body)-64 and size==was_new==0 and body[64:]==message.encode(),'complete race diagnostic')
        require(stable_nodes(after)==stable_nodes(actor.record['after']),'failed publication preserves actual external-writer result')
        return {'error':message,'publication_observed_before_error':description['race']['published']}
    require(tag==0 and len(body)==160 and error_len==0 and body[152:]==b'\0'*8,'race success layout')
    target=description['race']['after_target_base64'];matches=[row for row in after if row['path_base64']==target]
    require(len(matches)==1 and matches[0]['kind']=='file','actual result pathname after interleaving')
    observed=matches[0];native_output=expected_output(description)
    actual_want=materialize(description['race']['actual_data'])
    actual=(Path(blobs)/observed['data']['file']).read_bytes()
    require(actual==actual_want,'complete actual external-writer final bytes')
    require(size==len(native_output) and body[120:152]==bytes.fromhex(digest(native_output)),'original prepublication digest contract')
    require(was_new==(description['request']['mode']==1),'race create result indicator')
    require(list(struct.unpack_from('<7Q',body,64))==observed['identity'],'race result version bound to actual final stat')
    require(observed['identity']==version(os.lstat(os.fsencode(fixture)+b'/'+unb64(target))),'actual final stat unchanged during capture')
    return {'native_bytes':size,'native_sha256':body[120:152].hex(),'actual_bytes':len(actual),
            'actual_sha256':digest(actual),'version':observed['identity'],
            'same_inode_external_overwrite_preserved':description['race']['action']['op']=='overwrite'}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--elf',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);parser.add_argument('--diagnostics',required=True,type=Path)
    args=parser.parse_args();args.elf=args.elf.resolve();args.output=args.output.resolve()
    require(os.geteuid()!=0,'race fixtures require ordinary account rights')
    args.output.mkdir(parents=True,exist_ok=False);blobs=args.output/'blobs';blobs.mkdir()
    fixtures=args.output/'fixtures';fixtures.mkdir();case_dir=args.output/'cases';case_dir.mkdir()
    cases=race_cases();corpus_pin=save_json(args.output/'corpus.json',cases)
    diagnostics=json.loads(args.diagnostics.read_bytes());elf_pin=file_pin(args.elf)
    source_names=('hia_native_text_publication_fixtures.py','qualify_hia_text_publication_native.py',Path(__file__).name)
    source_pins={name:file_pin(Path(__file__).with_name(name)) for name in source_names}
    started=time.monotonic();rows=[];process=None;sequence=0;generation=0
    try:
        process=SyncProcess(args.elf,args.output/'process')
        for ordinal,description in enumerate(cases):
            name=description['name'];root=case_dir/name;root.mkdir();fixture=fixtures/str(ordinal)
            setup_fixture(fixture,description['setup']);wire,request=request_bytes(fixture,description)
            (root/'input.bin').write_bytes(wire);before=snapshot(fixture,blobs);save_json(root/'before.json',before)
            actor=Actor(description,fixture,root,blobs);result=process.exchange(wire,name,actor)
            (root/'record.bin').write_bytes(result['record']);after=snapshot(fixture,blobs);save_json(root/'after.json',after)
            observation=verify_result(description,result,actor,after,blobs,diagnostics,fixture)
            require(result['generation']==generation+1 and result['sequence']>sequence,'race engine retained progression')
            first=sequence+1;generation=result['generation'];sequence=result['sequence']
            drop=b'HTXTQ001'+struct.pack('<7Q',2,0,0,0,0,generation,0)
            dropped=process.exchange(drop,name+'/drop');(root/'drop-record.bin').write_bytes(dropped['record'])
            require(dropped['code']==64 and dropped['phase']==0 and dropped['generation']==generation and dropped['sequence']==sequence,'race terminal DROP retained counters')
            require(dropped['payload']==b'HTXTR001'+struct.pack('<7Q',2,0,0,0,generation,sequence,0),'complete race DROP body')
            row={'name':name,'ordinal':ordinal,'status':'PASS','fixture':str(fixture),'request':request,
                 'generation':generation,'first_sequence':first,'last_sequence':sequence,'effects':sequence-first+1,
                 'actor_sequence':actor.record['trigger_receipt']['sequence'],'published':description['race']['published'],
                 'observation':observation,'input':file_pin(root/'input.bin'),'record':file_pin(root/'record.bin'),
                 'actor':file_pin(root/'actor.json')}
            save_json(root/'case.json',row);rows.append(row)
            print(json.dumps({'case':name,'status':'PASS','effects':row['effects'],'published':row['published']},sort_keys=True),flush=True)
        process_result=process.finish();process=None;receipts=receipt_records(args.output/'process/stderr.bin')
        require(len(receipts)==sequence,'complete real race effect capture')
        for row in rows:
            selected=[r for r in receipts if row['first_sequence']<=r['sequence']<=row['last_sequence']]
            require(len(selected)==row['effects'] and all(r['generation']==row['generation'] for r in selected),'race receipt identity')
            published=[r for r in selected if r['kind']==17 and r['errno']==0]
            require(len(published)==int(row['published']),'actual atomic rename is independent of later result success')
            require(any(r['sequence']==row['actor_sequence'] for r in selected),'actor bound to an actual receipt')
        effects_pin=save_json(args.output/'effects.json',receipts)
        require(file_pin(args.elf)==elf_pin,'race native ELF unchanged')
        require({name:file_pin(Path(__file__).with_name(name)) for name in source_names}==source_pins,'race source unchanged')
        result={'schema':'hepta.runtime.text-publication-native-races.v1','status':'PASS','cases':len(rows),
                'native_effects':len(receipts),'actual_external_mutations':len(rows),'injected_effect_results':0,
                'elapsed_seconds':time.monotonic()-started,'source_pins':source_pins,'corpus':corpus_pin,'effects':effects_pin,
                'native_elf':{'path':str(args.elf),**elf_pin},'process':process_result,'rows':rows,
                'original_comparison_complete':False,'syscall_fault_qualification_complete':False,
                'public_handler_complete':False,'whole_runtime_replaced':False}
        save_json(args.output/'RESULT.json',result)
        print(json.dumps({k:v for k,v in result.items() if k not in ('rows','process','source_pins')},sort_keys=True),flush=True)
    except BaseException as error:
        failure=repr(error)
        if process is not None:
            try:process.finish(failure)
            except BaseException as cleanup_error:failure+='; cleanup: '+repr(cleanup_error)
        save_json(args.output/'FAILURE.json',{'failure':failure,'completed_cases':rows,'elapsed_seconds':time.monotonic()-started})
        raise

if __name__=='__main__':main()
