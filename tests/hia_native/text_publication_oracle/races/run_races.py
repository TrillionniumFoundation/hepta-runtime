"""Actual external-writer replay of twenty completed native race cases."""
from pathlib import Path
import argparse,json,os,struct,sys,time
bootstrap=argparse.ArgumentParser(add_help=False)
bootstrap.add_argument('--ordinary-request',type=Path,required=True);bootstrap.add_argument('--ordinary-reader',type=Path,required=True)
boot,_=bootstrap.parse_known_args()
reference_selection=json.loads(boot.ordinary_request.read_bytes())
sys.path[:0]=[str(Path(__file__).absolute().parent),str(boot.ordinary_reader.absolute()),reference_selection['source']]
from common import require,pin,save,encoded,loads,frames,parse_wire,unb64,Files
from strict_reference import evidence as reference_evidence,semantic_state,alias_shape
from race_native_predecessor import evidence as race_native_evidence
from race_cases import race_cases
from ptrace_capture import Tracer
import hia_native_text_publication_fixtures as fixture
def source_pins(folder):
    return {str(p.relative_to(folder)):pin(p.read_bytes()) for p in sorted(Path(folder).rglob('*')) if p.is_file()}
def original_result(raw):
    require(raw[:8]==b'HTXPO001','whole unchanged original result')
    case_id,size=struct.unpack_from('<2Q',raw,8);require(len(raw)==24+size,'whole original output extent')
    result=loads(raw[24:]);require(result['case_id']==case_id,'original result identity');return result
class Controller:
    def __init__(self,descriptions,records,blobs):
        self.descriptions=descriptions;self.records=records;self.blobs=blobs;self.active=None;self.index=0
        self.source_stats=0;self.source_reads=0;self.renames=0;self.actors=[];self.events=[]
    def fire(self,tracer,entry,event,interval):
        require(self.active is not None,'actual case before actor')
        r=self.records[self.active];description=self.descriptions[self.active]
        require('actor' not in r,'one actual external mutation')
        before=fixture.snapshot(r['tree'],self.blobs);action=description['race']['action'];op=action['op']
        target=os.fsencode(r['tree'])+b'/'+unb64(description['expect']['target_base64'])
        status=(Path('/proc')/str(tracer.pid)/'status').read_bytes()
        require(('TracerPid:\t'+str(os.getpid())+'\n').encode() in status,'actual child stopped by this parent')
        registers=tracer.registers();require(registers==event['registers'],'child registers unchanged at actual stop')
        descriptors=[]
        for fd in sorted((Path('/proc')/str(tracer.pid)/'fd').iterdir(),key=lambda p:int(p.name)):
            s=fd.stat();descriptors.append({'fd':int(fd.name),'target_hex':os.fsencode(os.readlink(fd)).hex(),'identity':fixture.version(s)})
        started=time.monotonic_ns()
        if op=='append':
            with open(target,'ab',buffering=0) as stream:require(stream.write(fixture.materialize(action['data']))==action['data']['length'],'complete external append')
        elif op=='truncate':os.truncate(target,action['size'])
        elif op=='unlink':os.unlink(target)
        elif op in ('replace','create'):
            name=target+b'.actor-new' if op=='replace' else target
            with open(name,'xb',buffering=0) as stream:
                raw=fixture.materialize(action['data']);require(stream.write(raw)==len(raw),'complete external file write')
            os.chmod(name,0o600)
            if op=='replace':os.replace(name,target)
        elif op=='overwrite':
            raw=fixture.materialize(action['data']);old=os.lstat(target);require(len(raw)==old.st_size,'same-size external input')
            with open(target,'r+b',buffering=0) as stream:require(stream.write(raw)==len(raw),'complete in-place external write')
            new=os.lstat(target);require((old.st_dev,old.st_ino,old.st_size)==(new.st_dev,new.st_ino,new.st_size),'actual same-inode same-size overwrite')
        elif op=='chmod_and_mtime':
            old=os.lstat(target);os.chmod(target,action['mode']);os.utime(target,ns=(old.st_atime_ns,old.st_mtime_ns-2000000000))
        elif op=='symlink':
            name=target+b'.actor-link';os.symlink(unb64(action['target_base64']),name);os.replace(name,target)
        elif op=='rename_parent':os.rename(os.fsencode(r['tree'])+b'/'+unb64(action['from_base64']),os.fsencode(r['tree'])+b'/'+unb64(action['to_base64']))
        else:raise ValueError('unknown actual external action')
        finished=time.monotonic_ns();after=fixture.snapshot(r['tree'],self.blobs)
        require(tracer.registers()==registers,'no tracee register or instruction alteration')
        actor={'case_id':1000+self.active,'name':description['name'],'entry_event':entry['event'],'trigger_event':event['event'],
               'trigger_kind':event['kind'],'original_interval':interval,'operation':action,'monotonic_start_ns':started,
               'monotonic_end_ns':finished,'before':before,'after':after,'child_status_hex':status.hex(),
               'actual_fd_observations':descriptors,'child_registers_before':registers,'child_registers_after':tracer.registers(),
               'effect_results_injected':False,'tracee_memory_or_registers_written':False}
        save(r['case']/'actor.json',actor);r['actor']=actor;self.actors.append(actor)
    def entry(self,tracer,event):
        n=event['number'];args=event['args']
        if n==121 and args[0]>=900000000:
            cid,end=divmod(args[0]-900000000,2)
            if not end:
                require(self.active is None and cid==1000+self.index and not tracer.fd_live,'ordered actual begin marker with no borrowed FD')
                self.active=self.index;self.source_stats=0;self.source_reads=0;self.renames=0
                self.records[self.active]['begin_event']=event['event']
            return
        if self.active is None:return
        r=self.records[self.active];name=self.descriptions[self.active]['name']
        if name=='competing-create-after-random' and 'actor' not in r and n==257 and args[2]&0o300==0o300:
            self.fire(tracer,event,event,'after unchanged temp_name returned, before actual staging openat; no intervening filesystem syscall')
    def exit(self,tracer,entry,event):
        n=event['number'];ret=event['return'];args=event['args']
        if n==121 and args[0]>=900000000:
            cid,end=divmod(args[0]-900000000,2);require(ret==-3,'actual marker ESRCH')
            if end:
                require(self.active is not None and cid==1000+self.active and not tracer.fd_live,'ordered actual end marker after all owned FDs retired')
                r=self.records[self.active];require('actor' in r,'actual original trigger was reached')
                r['end_event']=event['event'];r['successful_renames']=self.renames
                r['after']=fixture.snapshot(r['tree'],self.blobs);save(r['case']/'after.json',r['after'])
                self.active=None;self.index+=1
            return
        if self.active is None:return
        desc=self.descriptions[self.active];name=desc['name'];r=self.records[self.active]
        owner=entry['details'].get('fd_owner');role=owner['role'] if owner is not None else None
        if n in (264,316) and ret==0:self.renames+=1
        if n==5 and ret==0 and role=='source':self.source_stats+=1
        if n==0 and ret>=0 and role=='source':self.source_reads+=1
        if 'actor' in r or ret<0:return
        trigger=None
        if name in ('grow-during-read','grow-past-reader-limit') and n==5 and role=='source' and self.source_stats==1:trigger='after first source fstat, before source eligibility/read'
        elif name=='shrink-during-read' and n==0 and role=='source' and self.source_reads==1:trigger='after first real source read completed'
        elif name in ('replace-open-path','unlink-open-path') and n==257 and tracer.fd_live.get(ret,{}).get('role')=='source':trigger='after source openat, before its first fstat'
        elif name in ('replace-after-final-source-stat','unlink-after-final-source-stat') and n==5 and role=='source' and self.source_stats==2:trigger='after second source fstat completed'
        elif name in ('replace-before-publish','unlink-before-publish','chmod-before-publish') and n==3 and role=='stage':trigger='after staging close, before final source pathname check'
        elif name in ('competing-create-before-probe','held-parent-directory-renamed') and n==73:trigger='after advisory parent flock completed'
        elif name=='replace-after-final-source-check' and n==262 and not self.renames:trigger='after final source pathname fstatat, before atomic rename'
        elif name in ('unlink-after-rename','same-inode-same-size-overwrite-after-rename','shrink-after-rename','extend-after-rename','replace-inode-after-rename','symlink-after-rename') and n in (264,316):trigger='after actual atomic rename completed, before directory fsync'
        if trigger is not None:self.fire(tracer,entry,event,trigger)
def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--native-corpus',type=Path,required=True);p.add_argument('--ordinary-request',type=Path,required=True);p.add_argument('--ordinary-reader',type=Path,required=True);args=p.parse_args()
    source=args.source.absolute();out=args.output.absolute();nroot=args.native_corpus.absolute()
    out.mkdir(parents=True,exist_ok=False);os.umask(0o077)
    save(out/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text(),'started_monotonic_ns':time.monotonic_ns()})
    started=time.monotonic_ns();before_sources=source_pins(source);save(out/'SOURCE-FILES.json',before_sources)
    reference_raw=args.ordinary_request.read_bytes();ref_request=loads(reference_raw)
    require(ref_request['native_root']==str(nroot),'same complete native corpus for ordinary and races')
    reference_input={'path':str(args.ordinary_request.absolute()),**pin(reference_raw)}
    reader=args.ordinary_reader.absolute();reader_pins={n:pin((reader/n).read_bytes()) for n in ('strict_reference.py','trace_evidence.py')}
    save(out/'ORDINARY-READERS.json',reader_pins);native_files=Files(ref_request['origins'])
    ref=reference_evidence(**ref_request);(out/'ORDINARY-REQUEST.json').write_bytes(reference_raw);reference_pin=save(out/'ORDINARY-EVIDENCE.json',ref)
    native=race_native_evidence(nroot,ref_request['origins']);native_pin=save(out/'NATIVE-PREDECESSOR.json',native)
    admitted_ns=time.monotonic_ns()
    binary=Path(ref_request['output'])/'original.elf';binary_pin=pin(binary.read_bytes())
    descriptions=race_cases();require(len(descriptions)==20,'exact frozen twenty races')
    save(out/'corpus.json',descriptions);blobs=out/'blobs';blobs.mkdir();trees=out/'fixtures';trees.mkdir();cases=out/'cases';cases.mkdir()
    records=[];stdin=bytearray()
    for i,desc in enumerate(descriptions):
        case=cases/desc['name'];case.mkdir();tree=trees/str(i);fixture.setup_fixture(tree,desc['setup'])
        wire,projection=fixture.request_bytes(tree,desc);(case/'input.bin').write_bytes(wire)
        original_mode,path,expected,text=parse_wire(wire)
        nwire=native_files.raw(nroot/'domains/races/cases'/desc['name']/'input.bin');nm,np,ne,nt=parse_wire(nwire)
        require((original_mode,expected,text)==(nm,ne,nt),'unchanged entire admitted native race input')
        before=fixture.snapshot(tree,blobs);save(case/'before.json',before)
        nb=native_files.json(nroot/'domains/races/cases'/desc['name']/'before.json')
        require(semantic_state(before)==semantic_state(nb) and alias_shape(before)==alias_shape(nb),'whole initial state and inode alias shape')
        frame=b'HTXPI001'+struct.pack('<3Q',1000+i,len(wire),0)+wire
        stdin.extend(struct.pack('<Q',len(frame))+frame)
        records.append({'case_id':1000+i,'name':desc['name'],'ordinal':i,'tree':tree,'case':case,'wire':wire,'request':projection,'before':before})
    (out/'input.bin').write_bytes(stdin);control=Controller(descriptions,records,blobs)
    tracer=Tracer(binary,out/'input.bin',out,out/'process',control.entry,control.exit)
    process=tracer.run();require(process['started_monotonic_ns']>admitted_ns,'strict actual native-before-original replay order')
    require(control.active is None and control.index==20 and len(control.actors)==20,'all original races completed')
    require((out/'process/stderr').read_bytes()==b'','complete original race stderr')
    outputs=frames((out/'process/stdout').read_bytes());require(len(outputs)==20,'complete actual original race replies')
    rows=[];ok=0;err=0;published=0;actual_bytes=0
    for i,(raw,r,desc) in enumerate(zip(outputs,records,descriptions)):
        answer=original_result(raw);require(answer['case_id']==1000+i,'ordered original race case')
        case=r['case'];(case/'record.bin').write_bytes(raw);save(case/'original.json',answer)
        ncase=nroot/'domains/races/cases'/desc['name'];nrecord=native_files.raw(ncase/'record.bin');body=nrecord[64:]
        tag,elen,size,new,gen,seq,z=struct.unpack_from('<7Q',body,8)
        require(answer['ok'] is (tag==0),'whole original/native race success/error')
        na=native_files.json(ncase/'after.json')
        require(semantic_state(r['after'])==semantic_state(na) and alias_shape(r['after'])==alias_shape(na),'whole original/native post-race content metadata and alias relationships')
        require(r['successful_renames']==int(desc['race']['published']),'actual rename outcome independent of returned success')
        published+=r['successful_renames']
        if answer['ok']:
            require(set(answer)=={'case_id','ok','bytes','sha256','version','was_new_file'},'complete original race success body')
            require(answer['bytes']==size and answer['sha256']==body[120:152].hex() and answer['was_new_file'] is bool(new),'full unchanged original success projection')
            target=next(x for x in r['after'] if x['path_base64']==desc['race']['after_target_base64'])
            require(answer['version']==':'.join(map(str,target['identity'])),'returned version bound to actual own post-race inode')
            actual=(blobs/target['data']['file']).read_bytes()
            require(actual==fixture.materialize(desc['race']['actual_data']),'complete real external-writer final bytes')
            require(answer['sha256']==fixture.digest(fixture.expected_output(desc)),'returned digest still identifies prepublication output')
            actual_bytes+=len(actual);ok+=1
        else:
            require(set(answer)=={'case_id','ok','short','chain','errno'},'complete original race error and chain')
            require(answer['short'].encode()==body[64:],'complete original/native race error bytes');err+=1
        row={'case_id':1000+i,'name':desc['name'],'ordinal':i,'fixture':str(r['tree']),'request':r['request'],
             'input':pin(r['wire']),'record':pin(raw),'original':pin((case/'original.json').read_bytes()),
             'before':pin((case/'before.json').read_bytes()),'after':pin((case/'after.json').read_bytes()),
             'actor':pin((case/'actor.json').read_bytes()),'begin_event':r['begin_event'],'end_event':r['end_event'],
             'successful_renames':r['successful_renames'],'native_case':str(ncase)}
        save(case/'case.json',row);rows.append(row)
    require(source_pins(source)==before_sources and pin(binary.read_bytes())==binary_pin,'all executed source and original ELF bytes unchanged')
    require(race_native_evidence(nroot,ref_request['origins'])==native,'all actual native race predecessor bytes unchanged')
    require(reader_pins=={n:pin((reader/n).read_bytes()) for n in reader_pins},'actual ordinary reader bytes unchanged')
    result={'schema':'hepta.runtime.text-publication-original-races.v1','status':'PASS','cases':20,
            'successes':ok,'errors':err,'successful_atomic_renames':published,'actual_final_success_file_bytes':actual_bytes,
            'actual_external_mutations':20,'original_replay_processes':1,'new_fresh_builds':0,'new_native_calls':0,
            'reused_original_binary':{'path':str(binary),**binary_pin},'ordinary_reference_evidence':reference_pin,
            'native_predecessor':native_pin,'native_predecessor_checked_monotonic_ns':admitted_ns,
            'input':pin((out/'input.bin').read_bytes()),'process':process,'source_files':pin((out/'SOURCE-FILES.json').read_bytes()),
            'ordinary_request_input':reference_input,'ordinary_reader':str(reader),'ordinary_readers':pin((out/'ORDINARY-READERS.json').read_bytes()),
            'rows':rows,'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),
            'unchanged_linux_publish_executed':True,'syscall_results_injected':False,'tracee_instructions_modified':False,
            'getrandom_followup_trigger':'before staging openat after unchanged temp_name; libc may obtain entropy through vDSO',
            'actual_original_stat_fields_preserved':True,'public_handler_complete':False,'whole_runtime_replaced':False}
    save(out/'RESULT.json',result)
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows','process')},sort_keys=True),flush=True)
if __name__=='__main__':main()
