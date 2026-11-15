"""Physical, coherently re-signed refusals of complete original external-writer records."""
from pathlib import Path
import argparse,json,os,struct,sys,time
p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--reader',type=Path,action='append',required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();sys.path[:0]=list(map(str,a.reader))
from common import require,pin,save,loads,encoded,Files
from strict_races import evidence
OUT=a.output.absolute();OUT.mkdir()
save(OUT/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text(),'started_monotonic_ns':time.monotonic_ns()})
REQUEST=loads(a.request.read_bytes());CAP=Path(REQUEST['output']);SOURCE=Path(REQUEST['source']);PARENT=Path(REQUEST['outer_receipt']).parent
save(OUT/'REQUEST.json',REQUEST)
sources={str(x):pin(x.read_bytes()) for d in a.reader for x in d.rglob('*') if x.is_file()}
sources[str(Path(__file__))]=pin(Path(__file__).read_bytes());sources[str(a.request)]=pin(a.request.read_bytes());save(OUT/'SOURCE.json',sources)
start=time.monotonic_ns();baseline=evidence(**REQUEST);bp=save(OUT/'BASELINE.json',baseline)
basefiles=Files(REQUEST['origins'])
class Overlay:
    def __init__(self,name):
        self.root=OUT/'controls'/name;self.root.mkdir(parents=True);self.raws={};self.missing=set();self.symlinks=set()
    def get(self,path):return self.raws[str(path)] if str(path) in self.raws else basefiles.raw(path)
    def value(self,path):return loads(self.get(path))
    def put(self,path,raw):self.raws[str(path)]=raw
    def obj(self,path,value):self.put(path,encoded(value))
    def mutate(self,path,edit):
        x=self.value(path);edit(x);self.obj(path,x)
    def resign(self):
        s=self.value(CAP/'RESULT.json');s['process']=self.value(CAP/'process/PROCESS.json')
        self.obj(CAP/'RESULT.json',s);raw=encoded({k:v for k,v in s.items() if k not in ('rows','process')})
        self.put(PARENT/'stdout',raw);self.mutate(Path(REQUEST['outer_receipt']),lambda x:x.update(stdout=pin(raw)))
    def process(self,edit):
        self.mutate(CAP/'process/PROCESS.json',edit);self.resign()
    def trace(self,edit):
        path=CAP/'process/syscalls.jsonl';rows=[loads(x) for x in self.get(path).split(b'\n') if x];edit(rows)
        raw=b''.join(encoded(x) for x in rows);self.put(path,raw);self.process(lambda x:x.update(syscalls=pin(raw)))
    def rowfile(self,name,which,edit):
        s=self.value(CAP/'RESULT.json');r=next(x for x in s['rows'] if x['name']==name);path=CAP/'cases'/name/(which+'.json')
        value=self.value(path);edit(value);raw=encoded(value);self.put(path,raw);r[which]=pin(raw)
        self.obj(CAP/'cases'/name/'case.json',r);self.obj(CAP/'RESULT.json',s);self.resign()
    def materialize(self):
        origins=list(REQUEST['origins']);m={}
        for i,(old,raw) in enumerate(sorted(self.raws.items())):
            new=self.root/('file-'+str(i));new.write_bytes(raw);origins.append((old,str(new)));m[old]={'path':str(new),**pin(raw)}
        for i,old in enumerate(sorted(self.missing)):
            new=self.root/('absent-'+str(i));origins.append((old,str(new)));m[old]={'path':str(new),'absent':True}
        for i,old in enumerate(sorted(self.symlinks)):
            new=self.root/('symlink-'+str(i));new.symlink_to(basefiles.path(old));origins.append((old,str(new)));m[old]={'path':str(new),'symlink_target':str(basefiles.path(old))}
        save(self.root/'MUTATIONS.json',m);return origins,m
rows=[]
def control(group,name,edit,wants):
    o=Overlay(name);edit(o);origins,m=o.materialize();t=time.monotonic_ns()
    try:evidence(**{**REQUEST,'origins':origins})
    except (ValueError,KeyError,FileNotFoundError,UnicodeError,struct.error,StopIteration) as e:
        message=str(e);require(any(x in message for x in wants),'wrong rejection '+name+': '+repr(e))
        row={'group':group,'name':name,'status':'REJECTED','exception':type(e).__name__,'message':message,'mutations':m,'elapsed_seconds':(time.monotonic_ns()-t)/1e9}
    else:raise ValueError('accepted damaged complete evidence: '+name)
    retired=[]
    for original in sorted(o.symlinks):
        entry=m[original];path=Path(entry['path']);st=path.lstat()
        require(path.parent==o.root and (st.st_mode&0o170000)==0o120000 and os.readlink(path)==entry['symlink_target'],'exact owned negative-test symlink')
        record={'path':str(path),'target':entry['symlink_target'],'identity':{'dev':st.st_dev,'ino':st.st_ino,'mode':st.st_mode,'uid':st.st_uid,'gid':st.st_gid}}
        path.unlink();require(not os.path.lexists(path),'owned negative-test symlink retired');record['removed']=True;retired.append(record)
    row['retired_links']=retired;save(o.root/'LINK-RETIREMENT.json',retired)
    save(o.root/'RESULT.json',row);rows.append(row)
def flip(o,path):
    raw=o.get(path);require(raw,'nonempty corruption target');o.put(path,raw[:-1]+bytes([raw[-1]^1]))
def root_change(key,value):
    def go(o):o.mutate(CAP/'RESULT.json',lambda x:x.update({key:value}));o.resign()
    return go
def select(rows,predicate):return next(x for x in rows if predicate(x))
control('actual-process','changed-deadline',lambda o:o.process(lambda x:x.update(timeout_seconds=181)),['actual unchanged 180-second budget'])
control('actual-process','missing-timeout-result',lambda o:o.process(lambda x:x.pop('timed_out')),['timed_out'])
control('actual-process','non-null-start-error',lambda o:o.process(lambda x:x.update(start_error='injected')),['successful real original process'])
control('actual-process','boolean-pid',lambda o:o.process(lambda x:x.update(pid=True)),['actual PID'])
control('actual-process','zero-duration',lambda o:o.process(lambda x:x.update(elapsed_seconds=0)),['actual process duration'])
control('actual-process','injected-original-result',lambda o:o.process(lambda x:x.update(syscall_results_injected=1)),['observation without memory/register/result injection'])
control('complete-bytes','truncated-input',lambda o:o.put(CAP/'input.bin',o.get(CAP/'input.bin')[:-1]),['retained bytes/hash changed'])
control('complete-bytes','changed-complete-output',lambda o:flip(o,CAP/'process/stdout'),['retained bytes/hash changed'])
control('complete-bytes','truncated-trace',lambda o:o.trace(lambda x:x.pop()),['all trace records accounted'])
tr=[loads(x) for x in basefiles.raw(CAP/'process/syscalls.jsonl').split(b'\n') if x]
memory=next(x['details']['data'] for x in tr if x.get('details',{}).get('data'))
memorypath=CAP/'process/blobs'/memory['file']
control('complete-bytes','missing-actual-memory-buffer',lambda o:o.missing.add(str(memorypath)),['No such file or directory'])
control('complete-bytes','symlinked-memory-buffer',lambda o:o.symlinks.add(str(memorypath)),['symlink in retained path'])
binary=Path(basefiles.json(CAP/'RESULT.json')['reused_original_binary']['path'])
control('complete-bytes','changed-actual-original-elf',lambda o:flip(o,binary),['retained bytes/hash changed','retained hash changed'])
def wrongarg(xs):
    row=select(xs,lambda x:x['kind']=='entry');row['registers']['rdi']^=1
control('kernel-trace','register-arg-disagreement',lambda o:o.trace(wrongarg),['whole entry args/info/registers agree'])
def wrongret(xs):
    row=select(xs,lambda x:x['kind']=='exit-syscall');raw=bytearray.fromhex(row['syscall_info_hex']);raw[24]^=1;row['syscall_info_hex']=raw.hex()
control('kernel-trace','syscall-info-return-disagreement',lambda o:o.trace(wrongret),['complete exit info/register return'])
def wrongfd(xs):
    row=select(xs,lambda x:x.get('details',{}).get('fd_owner'));row['details']['fd_owner']['role']='stage-invalid'
control('kernel-trace','changed-fd-owner',lambda o:o.trace(wrongfd),['actual descriptor owner at syscall entry'])
def wrongmarker(xs):
    row=select(xs,lambda x:x['kind']=='entry' and x['number']==121 and x['args'][0]>=900000000)
    row['args'][0]+=2;row['registers']['rdi']+=2;raw=bytearray.fromhex(row['syscall_info_hex']);struct.pack_into('<Q',raw,32,row['args'][0]);row['syscall_info_hex']=raw.hex()
control('kernel-trace','coherent-wrong-marker-order',lambda o:o.trace(wrongmarker),['strict actual begin marker order'])
def wrongstat(xs):
    row=select(xs,lambda x:x.get('details',{}).get('stat'));row['details']['stat']['version'][1]+=1
control('kernel-trace','changed-stat-projection',lambda o:o.trace(wrongstat),['full actual stat byte projection'])
def wrongmemory(o):
    def edit(xs):
        row=select(xs,lambda x:x['kind']=='exit-syscall' and x['number']==0 and x['args'][0]==0 and x['return']>0)
        old=row['details']['data'];raw=basefiles.raw(CAP/'process/blobs'/old['file']);raw=bytes([raw[0]^1])+raw[1:]
        new={**pin(raw),'file':pin(raw)['sha256']+'.bin'};o.put(CAP/'process/blobs'/new['file'],raw);row['details']['data']=new
    o.trace(edit)
control('kernel-trace','coherent-changed-actual-stdin-read',wrongmemory,['every original stdin byte actually read'])
name='grow-during-read'
control('actual-writer','changed-actor-boundary',lambda o:o.rowfile(name,'actor',lambda x:x.update(trigger_event=x['trigger_event']+1)),['actual corresponding original syscall boundary'])
control('actual-writer','changed-after-register',lambda o:o.rowfile(name,'actor',lambda x:x['child_registers_after'].__setitem__('rax',x['child_registers_after']['rax']^1)),['original instructions/registers unchanged'])
control('actual-writer','changed-operation',lambda o:o.rowfile(name,'actor',lambda x:x['operation'].update(op='truncate')),['actual unchanged mutation input'])
control('actual-writer','late-actor-time',lambda o:o.rowfile(name,'actor',lambda x:x.update(monotonic_end_ns=basefiles.json(CAP/'process/PROCESS.json')['finished_monotonic_ns'])),['actual mutation completed before next original syscall stop'])
control('actual-writer','missing-owned-fd-observation',lambda o:o.rowfile(name,'actor',lambda x:x['actual_fd_observations'].pop()),['every actual live FD at actor boundary'])
control('actual-writer','changed-actual-tracee-identity',lambda o:o.rowfile(name,'actor',lambda x:x.update(child_status_hex=x['child_status_hex'].replace(b'TracerPid:'.hex(),b'NoTraceId:'.hex(),1))),['actual observer/tracee identity'])
control('state-and-response','changed-own-before-mode',lambda o:o.rowfile(name,'before',lambda x:x[0].update(mode=0o755)),['whole actual initial race content/metadata'])
control('state-and-response','changed-own-final-mode',lambda o:o.rowfile(name,'after',lambda x:x[0].update(mode=0o755)),['whole actual final race content/metadata'])
control('state-and-response','changed-complete-error',lambda o:o.rowfile(name,'original',lambda x:x.update(short=x['short']+'x')),['full parsed original body'])
def sameinode(o):
    n='same-inode-same-size-overwrite-after-rename'
    o.rowfile(n,'actor',lambda x:next(y for y in x['after'] if y['kind']=='file')['identity'].__setitem__(1,1))
control('state-and-response','changed-real-inplace-inode',sameinode,['actual external in-place mutation identity'])
def heldparent(o):
    n='held-parent-directory-renamed'
    def edit(x):
        p=next(y for y in x['after'] if y['kind']=='directory' and y['path_base64']);p['identity'][1]+=1
    o.rowfile(n,'actor',edit)
control('state-and-response','changed-held-parent-inode',heldparent,['same held parent inode across external rename'])
def wrongoutputcount(o):
    s=o.value(CAP/'RESULT.json');s['rows'][0]['successful_renames']=1;o.obj(CAP/'cases'/s['rows'][0]['name']/'case.json',s['rows'][0]);o.obj(CAP/'RESULT.json',s);o.resign()
control('state-and-response','changed-successful-rename-observation',wrongoutputcount,['actual rename before later outcome'])
control('source-and-domain','duplicate-json-key',lambda o:o.put(CAP/'RESULT.json',o.get(CAP/'RESULT.json').replace(b'"status":"PASS"',b'"status":"PASS","status":"PASS"',1)),['duplicate JSON object member'])
control('source-and-domain','nan-count',lambda o:o.put(CAP/'RESULT.json',o.get(CAP/'RESULT.json').replace(b'"cases":20',b'"cases":NaN',1)),['non-finite JSON literal'])
control('source-and-domain','boolean-case-count',root_change('cases',True),['typed exact actual race domain count'])
control('source-and-domain','public-scope-inflation',root_change('public_handler_complete',True),['no public/runtime scope inflation'])
control('source-and-domain','changed-observer-source',lambda o:flip(o,SOURCE/'ptrace_capture.py'),['retained bytes/hash changed'])
def changedpred(o):
    o.mutate(CAP/'NATIVE-PREDECESSOR.json',lambda x:x.update(new_native_calls=1))
    o.mutate(CAP/'RESULT.json',lambda x:x.update(native_predecessor=pin(o.get(CAP/'NATIVE-PREDECESSOR.json'))));o.resign()
control('source-and-domain','resigned-false-native-predecessor',changedpred,['all actual native races precede original replay'])
require(len(rows)==36 and len({x['name'] for x in rows})==36,'complete 36 refusal controls')
require({g:sum(x['group']==g for x in rows) for g in {x['group'] for x in rows}}=={g:6 for g in {x['group'] for x in rows}},'six groups of six')
require(encoded(evidence(**REQUEST))==encoded(baseline),'whole unchanged original evidence after refusal controls')
require(all(pin(Path(k).read_bytes())==v for k,v in sources.items()),'all executed source bytes unchanged')
result={'schema':'hepta.runtime.text-publication-original-race-refusals.v1','status':'PASS','groups':6,'controls':36,'rows':rows,'source':sources,'baseline':bp,'new_original_processes':0,'new_native_calls':0,'elapsed_seconds':(time.monotonic_ns()-start)/1e9,'unchanged_whole_evidence_after_controls':True}
save(OUT/'RESULT.json',result);print(json.dumps({k:v for k,v in result.items() if k not in ('rows','source')},sort_keys=True),flush=True)
