"""Physical native-evidence refusals and two real absent-origin read checks.

Only private hardlink snapshots are modified; a link is unlinked before every
replacement. Relocation moves our five explicitly admitted frozen roots and
always restores the same directory inodes. No native/Rust process is executed.
"""
from pathlib import Path
import argparse, copy, gzip, hashlib, importlib.util, json, os, shutil, signal, struct, subprocess, sys, time, traceback
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_text_publication_qualification as q

def raw_json(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(raw_json(value))
def digest(path):return q.pin(path.read_bytes())

class Snapshot:
    def __init__(self,root,config,baseline):
        self.root=root;root.mkdir();self.config=dict(config);self.config['origins']={}
        originals=q.Files({k:config[k] for k in ('native','boundary','faults','corpus','handoff')},config.get('origins'))
        self.originals={};self.changed={}
        for key,pin in baseline['artifact_sha256'].items():
            group,name=key.split('/',1);target=root/group/name;target.parent.mkdir(parents=True,exist_ok=True)
            source=originals.physical(originals.roots[group]+'/'+name)
            os.link(source,target);self.originals[key]=source
        for group in originals.roots:self.config['origins'][originals.roots[group]]=str(root/group)
    def path(self,key):return self.root/key
    def read(self,key):return self.path(key).read_bytes()
    def obj(self,key):return q.decode(self.read(key))
    def put(self,key,raw):
        path=self.path(key)
        if key not in self.changed:self.changed[key]=q.pin(path.read_bytes()) if path.exists() else None
        if path.exists():path.unlink()
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(raw)
    def putobj(self,key,value):self.put(key,raw_json(value))
    def remove(self,key):
        if key not in self.changed:self.changed[key]=q.pin(self.read(key))
        self.path(key).unlink()
    def edit(self,key,callback):
        value=self.obj(key);callback(value);self.putobj(key,value)
    def reset(self):
        for key in self.changed:
            path=self.path(key)
            if path.exists() or path.is_symlink():path.unlink()
            if key in self.originals:os.link(self.originals[key],path)
        self.changed={}
    def mechanical_resign(self):
        index=self.obj('handoff/ARTIFACTS.json')
        groups={'native':'native-v4','boundary':'boundary-v1','faults':'faults-v1'}
        for key in list(self.changed):
            group,name=key.split('/',1)
            if group in groups and name in index[groups[group]]['artifacts'] and self.path(key).exists():
                index[groups[group]]['artifacts'][name]=q.pin(self.read(key))
        self.putobj('handoff/ARTIFACTS.json',index)
    def refresh_corpus(self,domain):
        folder='corpus/domains/'+domain
        result=self.obj(folder+'/RESULT.json');child=self.obj(folder+'/process/process.json')
        for name in ('stdin','stdout','stderr'):
            child['streams'][name].update(q.pin(self.read(folder+'/process/'+name+'.bin')))
        self.putobj(folder+'/process/process.json',child);result['process']=child
        result['rows']=[self.obj(folder+'/cases/'+r['name']+'/case.json') for r in result['rows']]
        result['effects']=q.pin(self.read(folder+'/effects.json'))
        result['corpus']=q.pin(self.read(folder+'/corpus.json'))
        self.putobj(folder+'/RESULT.json',result)
        messages=[]
        for row in result['rows']:
            message={'case':row['name'],'status':'PASS','effects':row['effects']}
            message['published' if domain=='races' else 'code']=row['published' if domain=='races' else 'code']
            messages.append(message)
        messages.append({k:v for k,v in result.items() if k not in ('rows','process','source_pins')})
        self.put('corpus/'+domain+'.stdout',b''.join((json.dumps(x,sort_keys=True)+'\n').encode() for x in messages))
        proc=self.obj('corpus/'+domain+'.process.json')
        for stream in ('stdout','stderr'):proc[stream]=q.pin(self.read('corpus/'+domain+'.'+stream))
        self.putobj('corpus/'+domain+'.process.json',proc)
        top=self.obj('corpus/RESULT.json')
        for i,row in enumerate(top['domains']):
            if row['domain']==domain:top['domains'][i]=dict(proc,result=q.pin(self.read(folder+'/RESULT.json')),cases=result['cases'],native_effects=result['native_effects'])
        self.putobj('corpus/RESULT.json',top)
    def replace_record(self,domain,name,change):
        case='corpus/domains/'+domain+'/cases/'+name
        before=self.read(case+'/record.bin');after=change(before)
        q.same(len(after),len(before),'control preserves complete framing extent')
        self.put(case+'/record.bin',after)
        self.edit(case+'/case.json',lambda r:r.update(record=q.pin(after)))
        stream='corpus/domains/'+domain+'/process/stdout.bin'
        raw=self.read(stream);q.same(raw.count(before),1,'unique physical response to mutate')
        self.put(stream,raw.replace(before,after,1))
        def exchange(proc):
            for row in proc['exchanges']:
                if row['kind']==name:row['record_sha256']=q.sha(after)
        self.edit('corpus/domains/'+domain+'/process/process.json',exchange)
        self.refresh_corpus(domain)
    def private_buffer(self,group,folder,record_index,part_index,offset):
        key=group+'/'+folder
        meta=self.obj(key+'/capture.json');callable=group=='native'
        rows=meta['rows'] if callable else meta['records'];raw=bytearray(gzip.decompress(self.read(key+'/calls.bin.gz')))
        row=rows[record_index];at=row['offset'];head=72
        sizes=list(struct.unpack_from('<5Q',raw,at+32)) if callable else list(struct.unpack_from('<5Q',raw,at+32))
        pos=at+head+sum(sizes[:part_index])+offset
        raw[pos]^=1
        spans=[];cursor=at+head
        for size in sizes:spans.append(q.pin(raw[cursor:cursor+size]));cursor+=size
        row['spans']=spans;meta['raw_bytes']=len(raw);meta['raw_sha256']=q.sha(raw)
        self.put(key+'/calls.bin.gz',gzip.compress(raw,compresslevel=1,mtime=0));self.putobj(key+'/capture.json',meta)
        self.mechanical_resign()

def controls():
    # Each entry physically alters an admitted artifact. Re-signed entries also
    # update the surrounding full index/stream pins so semantic checks must fail.
    tests=[]
    def add(group,name,action,resigned=False):tests.append((group,name,action,resigned))
    add('source','modified-frozen-source',lambda s:s.put('native/source/native/text_publication.hepta',s.read('native/source/native/text_publication.hepta')+b'\n'))
    add('source','changed-machine-byte',lambda s:s.put('native/build/text-publication.elf',s.read('native/build/text-publication.elf')[:-1]+bytes([s.read('native/build/text-publication.elf')[-1]^1])))
    def missing(s):
        key='native/build/build/modules/text-publication/module.receipt.json';s.remove(key)
        s.edit('handoff/ARTIFACTS.json',lambda x:x['native-v4']['artifacts'].pop(key.split('/',1)[1]))
    add('source','removed-receipt-and-manifest-entry',missing,True)
    def original_path(s):
        s.edit('native/PROCESSES.json',lambda rows:rows[2]['command'].__setitem__(3,'/tmp/foreign-builder.py'));s.mechanical_resign()
    add('source','foreign-actual-builder-command',original_path,True)
    def missing_mapped(s):s.remove('native/source/scripts/text_publication_engine.S')
    add('source','no-fallback-to-existing-original-root',missing_mapped)
    def boolean_exit(s):s.edit('native/PROCESSES.json',lambda rows:rows[4].update(exit_code=False));s.mechanical_resign()
    add('process','boolean-success-exit',boolean_exit,True)
    def timeout(s):s.edit('faults/PROCESSES.json',lambda rows:rows[1].update(timed_out=True));s.mechanical_resign()
    add('process','actual-timeout',timeout,True)
    def deadline(s):s.edit('native/PROCESSES.json',lambda rows:rows[3].update(timeout_seconds=180.0));s.mechanical_resign()
    add('process','float-deadline',deadline,True)
    def pid(s):s.edit('corpus/ordinary.process.json',lambda row:row.update(pid=0))
    add('process','absent-real-pid',pid,True)
    def child_command(s):
        s.edit('corpus/domains/ordinary/process/process.json',lambda row:row['command'].append('--foreign'));s.refresh_corpus('ordinary')
    add('process','wrong-child-argv',child_command,True)
    def request_timeout(s):
        s.edit('corpus/domains/wide/process/process.json',lambda row:row['exchanges'][0].update(timeout_seconds=61));s.refresh_corpus('wide')
    add('process','changed-request-deadline',request_timeout,True)
    add('streams','complete-error-byte-replaced',lambda s:s.replace_record('ordinary','create-existing',lambda raw:raw[:128]+b'X'+raw[129:]),True)
    add('streams','success-digest-byte-replaced',lambda s:s.replace_record('ordinary','create-bytes-1',lambda raw:raw[:184]+bytes([raw[184]^1])+raw[185:]),True)
    def effect_repeat(s):
        key='corpus/domains/ordinary/process/stderr.bin';raw=s.read(key);s.put(key,raw[:256]+raw[:256]+raw[512:]);s.refresh_corpus('ordinary')
    add('streams','repeated-completed-effect',effect_repeat,True)
    def wrong_ack(s):
        key='corpus/domains/races/process/stdin.bin';raw=bytearray(s.read(key));at=raw.index(b'HTXTACK1');struct.pack_into('<Q',raw,at+16,0);s.put(key,raw);s.refresh_corpus('races')
    add('streams','late-or-wrong-identity-ack',wrong_ack,True)
    def nonfinite(s):
        key='corpus/domains/wide/process/process.json';raw=s.read(key);s.put(key,raw.replace(b'"elapsed_seconds":',b'"elapsed_seconds": NaN,"replaced_elapsed_seconds":',1))
    add('streams','nonfinite-duration',nonfinite)
    def private_state(s):s.private_buffer('native','callable-controls',0,4,4000)
    add('private','state-refusal-changes-workspace',private_state,True)
    add('private','capacity-refusal-changes-output',lambda s:s.private_buffer('boundary','controls',14,3,17),True)
    add('private','fd-refusal-changes-private-engine',lambda s:s.private_buffer('boundary','controls',18,3,320),True)
    def allocation(s):s.edit('native/callable-controls/allocations.json',lambda rows:rows[4].update(vmsize_after=rows[4]['vmsize_after']+4096));s.mechanical_resign()
    add('private','partial-create-leaks-real-map',allocation,True)
    def retry(s):
        s.edit('native/callable-controls/capture.json',lambda x:x['rows'][9]['engine_after'].update(sequence=x['rows'][9]['engine_after']['sequence']+1));s.mechanical_resign()
    add('private','output-retry-reexecutes-effects',retry,True)
    def kernel(s):
        key='faults/full/read-eintr/syscalls.json';events=s.obj(key);event=next(x for x in events if x['rule'])
        event['kernel_result']=-5;event['kernel_exit']['rax']=(-5)&q.U64;s.putobj(key,events);s.mechanical_resign()
    add('fault','hidden-kernel-result-replacement',kernel,True)
    def delivered(s):
        key='faults/full/read-partial/syscalls.json';events=s.obj(key);event=next(x for x in events if x['rule'])
        event['submitted_entry']['rdx']+=1;s.putobj(key,events);s.mechanical_resign()
    add('fault','wrong-real-short-count',delivered,True)
    def injected(s):
        key='faults/full/source-close-eintr/syscalls.json';events=s.obj(key);event=next(x for x in events if x['rule'])
        event['kernel_result']=-4;event['kernel_exit']['rax']=(-4)&q.U64;s.putobj(key,events);s.mechanical_resign()
    add('fault','close-eintr-without-real-close',injected,True)
    def stat_published(s):
        s.edit('faults/full/parent-fsync-eio/before-output.json',lambda x:x.update(published=0));s.mechanical_resign()
    add('fault','rollback-claim-after-publish',stat_published,True)
    def syscall_register(s):
        key='faults/full/replace/syscalls.json';events=s.obj(key);event=next(x for x in events if x.get('syscall')==257)
        event['kernel_exit']['rdi']^=1;event['delivered_exit']['rdi']^=1;s.putobj(key,events);s.mechanical_resign()
    add('fault','unreported-syscall-argument-change',syscall_register,True)
    def fd_leak(s):
        s.edit('faults/full/create/before-output.json',lambda x:x['proc_descriptors'].update({'3':'/tmp/still-owned'}));s.mechanical_resign()
    add('fault','actual-terminal-descriptor-remains',fd_leak,True)
    def changed_tree(s):
        key='corpus/domains/ordinary/cases/create-bytes-0/after.json';rows=s.obj(key);node=next(x for x in rows if x['kind']=='file')
        body=b'changed';item=q.pin(body);item['file']=item['sha256']+'.bin';node['data']=item;node['identity'][2]=len(body)
        s.put('corpus/domains/ordinary/blobs/'+item['file'],body);s.putobj(key,rows);s.refresh_corpus('ordinary')
    add('tree','complete-after-body-resigned',changed_tree,True)
    def no_before(s):
        key='corpus/domains/metadata/cases/refuse-hardlink/before.json';rows=s.obj(key);rows=[r for r in rows if q.unb64(r['path_base64'])!=b'other'];s.putobj(key,rows)
    add('tree','missing-hardlink-group-member',no_before,True)
    def actor_rule(s):
        s.edit('corpus/domains/races/cases/grow-during-read/actor.json',lambda row:row['operation'].update(op='replace'))
        key='corpus/domains/races/cases/grow-during-read/case.json'
        s.edit(key,lambda row:row.update(actor=q.pin(s.read(key.replace('case.json','actor.json')))));s.refresh_corpus('races')
    add('tree','actor-operation-does-not-match-input',actor_rule,True)
    def actor_injection(s):
        s.edit('corpus/domains/races/cases/grow-during-read/actor.json',lambda row:row.update(effect_results_injected=True));s.refresh_corpus('races')
    add('tree','race-injects-completion',actor_injection,True)
    def scope(s):
        s.edit('corpus/domains/ordinary/RESULT.json',lambda row:row.update(original_comparison_complete=True));s.refresh_corpus('ordinary')
    add('tree','native-only-claims-original-pass',scope,True)
    def parent_identity(s):
        s.edit('corpus/domains/races/cases/held-parent-directory-renamed/actor.json',lambda row:next(x for x in row['after'] if q.unb64(x['path_base64'])==b'moved')['identity'].__setitem__(1,0));s.refresh_corpus('races')
    add('tree','held-parent-inode-replaced',parent_identity,True)
    return tests

def run_controls(config,output,baseline):
    snapshots=Snapshot(output/'snapshot',config,baseline)
    q.same(q.native_evidence(**snapshots.config),baseline,'unaltered hardlink snapshot full evidence equality')
    cases=[]
    for index,(group,name,change,resigned) in enumerate(controls(),1):
        folder=output/'cases'/('%02d-'%index+name);folder.mkdir(parents=True)
        start=time.monotonic_ns();change(snapshots)
        changed={}
        for key,before in snapshots.changed.items():
            path=snapshots.path(key)
            if path.exists():
                raw=path.read_bytes();target=folder/'changed'/key;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
                changed[key]={'before':before,'after':q.pin(raw),'file':'changed/'+key}
            else:changed[key]={'before':before,'after':None,'file':None}
        require_error=None
        try:q.native_evidence(**snapshots.config)
        except (ValueError,OSError,KeyError,UnicodeError,struct.error) as error:
            require_error={'type':type(error).__name__,'message':str(error)}
        elapsed=(time.monotonic_ns()-start)/1e9
        row={'index':index,'group':group,'name':name,'resigned_surrounding_indices':resigned,
             'actual_physical_changes':changed,'elapsed_seconds':elapsed,'rejection':require_error,
             'status':'PASS' if require_error else 'FAIL','native_cases_added':0,'rust_cases_added':0}
        save(folder/'result.json',row);cases.append(row)
        print(json.dumps({k:row[k] for k in ('index','group','name','status','rejection')},sort_keys=True),flush=True)
        snapshots.reset()
        q.require(require_error is not None,'modified native evidence was accepted: '+name)
    q.same(q.native_evidence(**snapshots.config),baseline,'all private snapshot links restored')
    q.same(q.native_evidence(**config),baseline,'actual originals complete after all refusals')
    return {'cases':cases,'groups':len({r['group'] for r in cases}),'controls':len(cases),
            'physical_controls':sum(not r['resigned_surrounding_indices'] for r in cases),
            'resigned_controls':sum(r['resigned_surrounding_indices'] for r in cases),
            'baseline_unchanged':True,'snapshot_restored':True}

def invoke_reader(source,config,output):
    command=['/usr/bin/python3','-I','-B',str(source/'scripts/hia_native_text_publication_qualification.py'),
             '--config',str(config),'--output',str(output/'EVIDENCE.json')]
    start=time.monotonic_ns();pid=None;error=None;timed=False;code=None
    with (output/'stdout').open('xb') as stdout,(output/'stderr').open('xb') as stderr:
        try:
            child=subprocess.Popen(command,cwd=source,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True);pid=child.pid
            try:code=child.wait(timeout=180)
            except subprocess.TimeoutExpired:timed=True;os.killpg(pid,signal.SIGKILL);code=child.wait(timeout=10)
        except BaseException:error=traceback.format_exc()
    end=time.monotonic_ns()
    record={'command':command,'cwd':str(source),'pid':pid,'started_monotonic_ns':start,'finished_monotonic_ns':end,
            'elapsed_seconds':(end-start)/1e9,'timeout_seconds':180,'timed_out':timed,'start_error':error,'exit_code':code,
            'stdout':digest(output/'stdout'),'stderr':digest(output/'stderr'),
            'native_processes':0,'rust_processes':0}
    save(output/'PROCESS.json',record)
    q.require(code==0 and not timed and error is None,'relocated pure reader process failed')
    return record,q.decode((output/'EVIDENCE.json').read_bytes())

def run_relocations(config,output,baseline):
    # This action is opt-in and restricted to the five completed, exclusively
    # owned task roots. A pure native_evidence/retained caller never does it.
    q.require('origins' not in config,'real-absence controls require actual original roots')
    roots={key:Path(config[key]) for key in ('native','boundary','faults','corpus','handoff')}
    for path in roots.values():
        q.require(path.parent==Path('/home/qq') and path.name.startswith('hepta-text-publication-'),
                  'only this task exclusively owned completed roots may move')
        q.require(path.is_dir() and not path.is_symlink(),'actual owned root directory')
    copies=[]
    for number in (1,2):
        destination=output/('new-root-'+str(number));destination.mkdir()
        snapshot=Snapshot(destination/'output',config,baseline)
        source=destination/'source'
        for relative in ('scripts/hia_native_text_publication_qualification.py','native/text_publication_qualification_sources.json'):
            path=source/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((ROOT/relative).read_bytes())
        save(destination/'CONFIG.json',snapshot.config)
        copies.append((destination,source,snapshot))
    moved=[];before={};results=[]
    try:
        for role,path in roots.items():
            info=path.lstat();before[role]={'dev':info.st_dev,'ino':info.st_ino,'mode':info.st_mode,'uid':info.st_uid,'gid':info.st_gid}
            retained=path.with_name(path.name+'.text-reader-retained-'+str(os.getpid()))
            q.require(not retained.exists(),'unique retained root path')
            os.rename(path,retained);moved.append((role,path,retained))
        for _,path,_ in moved:
            try:path.lstat();raise AssertionError('original root still exists')
            except FileNotFoundError:pass
        for destination,source,snapshot in copies:
            (destination/'read').mkdir()
            process,evidence=invoke_reader(source,destination/'CONFIG.json',destination/'read')
            q.same(evidence,baseline,'whole relocated evidence object equality')
            for _,path,_ in moved:
                try:path.lstat();raise AssertionError('original unexpectedly recreated')
                except FileNotFoundError:pass
            # Every copied artifact was a regular admitted file; all producer
            # live-fixture paths are absent from the two read-only snapshots.
            q.require(not any(p.name in ('files','fixtures') for p in (destination/'output').rglob('*') if p.is_dir()),'new evidence contains no live fixtures')
            result={'new_source':str(source),'new_output':str(destination/'output'),'original_roots_absent':{k:True for k in roots},
                    'original_source_roots_absent':{k:True for k in ('native','boundary','faults','corpus')},
                    'original_fixture_roots_absent':True,'complete_object_equal':True,
                    'evidence':digest(destination/'read/EVIDENCE.json'),'process':process,
                    'native_processes':0,'rust_processes':0}
            save(destination/'RESULT.json',result);results.append(result)
    finally:
        for role,path,retained in reversed(moved):
            q.require(not path.exists(),'never overwrite an unexpectedly recreated origin')
            os.rename(retained,path)
    restored={}
    for role,path in roots.items():
        info=path.lstat();restored[role]={'dev':info.st_dev,'ino':info.st_ino,'mode':info.st_mode,'uid':info.st_uid,'gid':info.st_gid}
    q.same(restored,before,'same actual original directory inodes and ownership restored')
    q.same(q.native_evidence(**config),baseline,'all complete original artifacts unchanged after real absence')
    return {'positive_relocations':2,'reads':results,'directory_identity_before':before,
            'directory_identity_restored':restored,'complete_original_evidence_unchanged':True}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);parser.add_argument('--relocations-only',action='store_true')
    args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    config=q.decode(args.config.read_bytes());start=time.monotonic_ns()
    sources={str(p.relative_to(ROOT)):digest(p) for p in (Path(__file__).resolve(),Path(q.__file__).resolve(),q.CONTRACT)}
    save(output/'SOURCE-FILES.json',sources);save(output/'CONFIG.json',config)
    baseline=q.native_evidence(**config);save(output/'BASELINE.json',baseline)
    result={'schema':'hepta.runtime.text-publication-read-controls.v1','status':'RUNNING','mode':'relocations' if args.relocations_only else 'refusals',
            'source_pins':sources,'baseline':digest(output/'BASELINE.json'),'native_cases_added':0,'rust_cases_added':0,
            'native_processes':0,'rust_processes':0,'original_comparison_complete':False,
            'skipped':0,'errors':0,'failures':0}
    try:
        observed=run_relocations(config,output,baseline) if args.relocations_only else run_controls(config,output,baseline)
        result.update(observed);result['status']='PASS'
        q.same({str(p.relative_to(ROOT)):digest(p) for p in (Path(__file__).resolve(),Path(q.__file__).resolve(),q.CONTRACT)},sources,'all pure qualification source unchanged')
    except BaseException:
        result['status']='FAIL';result['errors']=1;result['traceback']=traceback.format_exc();raise
    finally:
        result['elapsed_seconds']=(time.monotonic_ns()-start)/1e9
        save(output/'RESULT.json',result)
        print(json.dumps({k:v for k,v in result.items() if k not in ('cases','reads','source_pins','traceback')},sort_keys=True),flush=True)

if __name__=='__main__':main()
