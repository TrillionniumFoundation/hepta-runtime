"""Physical/reforged ordinary original controls; selected roots remain explicit."""
from pathlib import Path
import argparse,json,os,re,struct,sys,time
p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--reader',type=Path,action='append',required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();sys.path[:0]=list(map(str,a.reader))
from common import require,pin,save,loads,encoded,frames,Files
from strict_reference import evidence
OUT=a.output.absolute();OUT.mkdir()
save(OUT/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text(),'started_monotonic_ns':time.monotonic_ns()})
REQUEST=loads(a.request.read_bytes());SOURCE=Path(REQUEST['source']);CAP=Path(REQUEST['output']);PARENT=Path(REQUEST['outer_receipt']).parent
save(OUT/'REQUEST.json',REQUEST)
PINS={str(p):pin(p.read_bytes()) for d in a.reader for p in d.rglob('*') if p.is_file()}
PINS[str(Path(__file__))]=pin(Path(__file__).read_bytes())
save(OUT/'SOURCE.json',PINS)
START=time.monotonic_ns();baseline=evidence(**REQUEST);basepin=save(OUT/'BASELINE.json',baseline);basefiles=Files(REQUEST['origins'])
class Overlay:
    def __init__(self,name):
        self.root=OUT/'controls'/name;self.root.mkdir(parents=True);self.raws={};self.missing=set();self.symlinks=set()
    def get(self,p):
        p=str(p);return self.raws[p] if p in self.raws else basefiles.raw(p)
    def value(self,p):return loads(self.get(p))
    def put(self,p,raw):self.raws[str(p)]=raw
    def obj(self,p,value):self.put(p,encoded(value))
    def mutate_json(self,p,action):
        obj=self.value(p);action(obj);self.obj(p,obj)
    def resign(self):
        summary=self.value(CAP/'RESULT.json')
        for name,key in (('SOURCE.json','source_manifest'),('SOURCE-FILES.json','source_files'),('PROCESSES.json','processes'),('TOOLS.json','toolchain'),('NATIVE-PREDECESSOR.json','native_predecessor')):
            summary[key]=pin(self.get(CAP/name))
        self.obj(CAP/'RESULT.json',summary)
        stdout=encoded({k:v for k,v in summary.items() if k!='rows'})
        self.put(PARENT/'stdout',stdout)
        outer=self.value(Path(REQUEST['outer_receipt']));outer['stdout']=pin(stdout)
        self.obj(Path(REQUEST['outer_receipt']),outer)
    def process(self,name,action):
        path=CAP/'processes'/name/'PROCESS.json';value=self.value(path);action(value);self.obj(path,value)
        procs=self.value(CAP/'PROCESSES.json')
        for row in procs:
            if row['name']==name:row.clear();row.update(name=name,**value);break
        else:raise ValueError('unknown process')
        self.obj(CAP/'PROCESSES.json',procs)
        if name.startswith('original-'):self.mutate_json(CAP/'domains'/name[9:]/'RESULT.json',lambda o:o.update(process=value))
        self.resign()
    def case_rows(self,domain,ordinal,action):
        d=CAP/'domains'/domain;dr=self.value(d/'RESULT.json');row=dr['rows'][ordinal];action(row)
        self.obj(d/'cases'/row['name']/'case.json',row);self.obj(d/'RESULT.json',dr)
        summary=self.value(CAP/'RESULT.json');summary['rows'][row['case_id']]=row;self.obj(CAP/'RESULT.json',summary)
        self.resign()
    def trace(self,domain,action):
        d=CAP/'domains'/domain;p=d/'strace.log';raw=action(self.get(p));self.put(p,raw)
        self.mutate_json(d/'RESULT.json',lambda o:o.update(trace=pin(raw)));self.resign()
    def state(self,domain,ordinal,which,action):
        d=CAP/'domains'/domain;row=self.value(d/'RESULT.json')['rows'][ordinal];p=d/'cases'/row['name']/(which+'.json')
        value=self.value(p);action(value);raw=encoded(value);self.put(p,raw)
        self.case_rows(domain,ordinal,lambda r:r.update({which:pin(raw)}))
    def input(self,domain,ordinal,action):
        d=CAP/'domains'/domain;row=self.value(d/'RESULT.json')['rows'][ordinal];p=d/'cases'/row['name']/'input.bin'
        wire=action(self.get(p));self.put(p,wire)
        parts=frames(self.get(d/'input.bin'));parts[ordinal]=b'HTXPI001'+struct.pack('<3Q',row['case_id'],len(wire),0)+wire
        raw=b''.join(struct.pack('<Q',len(x))+x for x in parts);self.put(d/'input.bin',raw)
        self.mutate_json(d/'RESULT.json',lambda o:o.update(input=pin(raw)))
        self.case_rows(domain,ordinal,lambda r:r.update(input=pin(wire)))
        self.process('original-'+domain,lambda r:r.update(stdin={'path':str(d/'input.bin'),**pin(raw)}))
    def materialize(self):
        origins=list(REQUEST['origins']);manifest={}
        for i,(origin,raw) in enumerate(sorted(self.raws.items())):
            p=self.root/('file-'+str(i));p.write_bytes(raw);origins.append((origin,str(p)));manifest[origin]={'path':str(p),**pin(raw)}
        for i,origin in enumerate(sorted(self.missing)):
            p=self.root/('absent-'+str(i));origins.append((origin,str(p)));manifest[origin]={'path':str(p),'absent':True}
        for i,origin in enumerate(sorted(self.symlinks)):
            p=self.root/('symlink-'+str(i));p.symlink_to(basefiles.path(origin));origins.append((origin,str(p)));manifest[origin]={'path':str(p),'symlink_target':str(basefiles.path(origin))}
        save(self.root/'MUTATIONS.json',manifest);return origins,manifest
rows=[]
def control(group,name,edit,expected):
    overlay=Overlay(name);edit(overlay);origins,manifest=overlay.materialize();request={**REQUEST,'origins':origins};started=time.monotonic_ns()
    try:evidence(**request)
    except (ValueError,KeyError,FileNotFoundError,UnicodeError,struct.error) as error:
        message=str(error);require(any(part in message for part in expected),'wrong rejection for '+name+': '+repr(error))
        row={'group':group,'name':name,'status':'REJECTED','exception':type(error).__name__,'message':message,'elapsed_seconds':(time.monotonic_ns()-started)/1e9,'mutations':manifest}
    else:raise ValueError('accepted corrupted evidence: '+name)
    retired=[]
    for original in sorted(overlay.symlinks):
        entry=manifest[original];path=Path(entry['path']);st=path.lstat()
        require(path.parent==overlay.root and (st.st_mode&0o170000)==0o120000 and os.readlink(path)==entry['symlink_target'],'exact owned negative-test symlink')
        record={'path':str(path),'target':entry['symlink_target'],'identity':{'dev':st.st_dev,'ino':st.st_ino,'mode':st.st_mode,'uid':st.st_uid,'gid':st.st_gid}}
        path.unlink();require(not os.path.lexists(path),'owned negative-test symlink retired');record['removed']=True;retired.append(record)
    row['retired_links']=retired;save(overlay.root/'LINK-RETIREMENT.json',retired)
    save(overlay.root/'RESULT.json',row);rows.append(row)
def root_change(key,value):
    def edit(o):o.mutate_json(CAP/'RESULT.json',lambda v:v.update({key:value}));o.resign()
    return edit

control('typed-json','duplicate-root-key',lambda o:o.put(CAP/'RESULT.json',o.get(CAP/'RESULT.json').replace(b'"status":"PASS"',b'"status":"PASS","status":"PASS"',1)),['duplicate JSON'])
control('typed-json','nan-count',lambda o:o.put(CAP/'RESULT.json',o.get(CAP/'RESULT.json').replace(b'"cases":99',b'"cases":NaN',1)),['non-finite JSON'])
control('typed-json','infinity-time',lambda o:o.put(CAP/'RESULT.json',o.get(CAP/'RESULT.json').replace(b'"started_monotonic_ns":',b'"unused":Infinity,"started_monotonic_ns":',1)),['non-finite JSON'])
control('typed-json','overflow-json-float',lambda o:o.put(CAP/'RESULT.json',o.get(CAP/'RESULT.json').replace(b'"cases":99',b'"cases":1e999',1)),['non-finite JSON'])
control('typed-json','boolean-case-count',root_change('cases',True),['typed actual original count'])
control('typed-json','boolean-build-count',root_change('fresh_locked_builds',True),['typed actual original count'])
control('typed-json','wrong-reference-schema',root_change('schema','hepta.runtime.unrelated.v1'),['complete actual original capture'])
control('actual-process','missing-timeout-status',lambda o:o.process('build',lambda p:p.pop('timed_out')),['complete actual process receipt fields'])
control('actual-process','changed-real-deadline',lambda o:o.process('build',lambda p:p.update(timeout_seconds=181)),['actual successful 180-second gate'])
control('actual-process','boolean-real-pid',lambda o:o.process('build',lambda p:p.update(pid=True)),['actual process PID'])
control('actual-process','removed-locked-command',lambda o:o.process('build',lambda p:p['command'].remove('--locked')),['actual fixed command'])
control('actual-process','wrong-explicit-rustc',lambda o:o.process('build',lambda p:p['recorded_environment'].update(RUSTC='/wrong/rustc')),['explicit selected compiler environment'])
control('actual-process','nonzero-replay-exit',lambda o:o.process('original-wide',lambda p:p.update(exit_code=1)),['actual successful 180-second gate'])
control('actual-process','boolean-parent-exit',lambda o:o.mutate_json(Path(REQUEST['outer_receipt']),lambda p:p.update(exit_code=False)),['typed actual parent scalar'])
def flip(o,p):
    b=bytearray(o.get(p));require(b,'nonempty mutation');b[len(b)//2]^=1;o.put(p,bytes(b))
control('complete-bytes','changed-original-linux-source',lambda o:flip(o,SOURCE/'original/text_file_write.rs'),['retained bytes/hash changed'])
control('complete-bytes','changed-original-elf',lambda o:flip(o,CAP/'original.elf'),['retained bytes/hash changed'])
control('complete-bytes','changed-compiler-binary',lambda o:flip(o,CAP/'tool-binaries/rustc'),['retained bytes/hash changed'])
control('complete-bytes','truncated-replay-input',lambda o:o.put(CAP/'domains/wide/input.bin',o.get(CAP/'domains/wide/input.bin')[:-1]),['retained bytes/hash changed'])
control('complete-bytes','truncated-complete-output',lambda o:o.put(CAP/'domains/ordinary/cases/create-bytes-0/record.bin',o.get(CAP/'domains/ordinary/cases/create-bytes-0/record.bin')[:-1]),['retained bytes/hash changed'])
blob=next(k for k,p in baseline['artifact_sha256'].items() if str(CAP/'domains/wide/blobs')+'/' in k and p['bytes']>4000000)
control('complete-bytes','changed-whole-published-file',lambda o:flip(o,blob),['retained bytes/hash changed'])
control('complete-bytes','unreported-stderr-byte',lambda o:o.put(CAP/'processes/original-ordinary/stderr',b'x'),['retained bytes/hash changed'])
def replace_once(raw,old,new):
    require(old in raw,'actual trace mutation target');return raw.replace(old,new,1)
control('actual-trace','wrong-first-marker',lambda o:o.trace('ordinary',lambda b:replace_once(b,b'getpgid(900000000)',b'getpgid(900000002)')),['unique ordered begin marker'])
def remove_call(raw,name):
    lines=raw.splitlines(keepends=True);found=next(i for i,x in enumerate(lines) if b' '+name+b'(' in x)
    return b''.join(lines[:found]+lines[found+1:])
control('actual-trace','missing-parent-fsync',lambda o:o.trace('ordinary',lambda b:remove_call(b,b'fsync')),['actual stage/data and parent fsync order'])
control('actual-trace','missing-generated-temp-cleanup',lambda o:o.trace('ordinary',lambda b:remove_call(b,b'unlinkat')),['post-rename original temp cleanup'])
control('actual-trace','lost-held-parent-close',lambda o:o.trace('ordinary',lambda b:remove_call(b,b'close')),['close of traced owned descriptor','ordered end marker','unique ordered begin marker','descriptor lifetime','newly owned'])
control('actual-trace','changed-atomic-rename-return',lambda o:o.trace('ordinary',lambda b:re.sub(rb'(renameat2\(.*?\)) = 0',rb'\1 = -1 EEXIST (File exists)',b,count=1)),['success actual atomic rename'])
def final_stat_wrong(raw):
    lines=raw.splitlines(keepends=True);target=None
    for i,line in enumerate(lines):
        if b'unlinkat(' in line:
            target=next(j for j in range(i+1,len(lines)) if b' newfstatat(' in lines[j]);break
    require(target is not None,'actual final stat target')
    lines[target]=re.sub(rb'st_ino=(\d+)',lambda m:b'st_ino='+str(int(m[1])+1).encode(),lines[target],count=1)
    return b''.join(lines)
control('actual-trace','changed-returned-inode-stat',lambda o:o.trace('ordinary',final_stat_wrong),['actual full kernel stat binds'])
control('actual-trace','unknown-recorded-syscall',lambda o:o.trace('ordinary',lambda b:replace_once(b,b'flock(',b'unknown_call(')),['unknown actual traced syscall'])

def changed_path(wire):
    b=bytearray(wire);pn=struct.unpack_from('<Q',b,24)[0];b[64+pn-1]^=1;return bytes(b)
control('semantic-binding','rewritten-owned-raw-path',lambda o:o.input('ordinary',0,changed_path),['original raw path unchanged'])
def changed_expected(wire):
    b=bytearray(wire);pn=struct.unpack_from('<Q',b,24)[0];b[64+pn]=ord('b');return bytes(b)
control('semantic-binding','changed-original-digest',lambda o:o.input('ordinary',0,changed_expected),['already admitted digest form'])
control('semantic-binding','changed-original-content',lambda o:o.input('ordinary',1,lambda b:b[:-1]+b'z'),['all admitted original/native content bytes'])
control('semantic-binding','changed-complete-final-mode',lambda o:o.state('ordinary',0,'after',lambda v:v[-1].update(mode=0o640)),['whole actual final metadata/content'])
control('semantic-binding','changed-own-final-stat',lambda o:o.state('ordinary',0,'after',lambda v:v[-1]['identity'].__setitem__(1,v[-1]['identity'][1]+1)),['seven actual inode stat fields'])
hard_index=next(i for i,r in enumerate(basefiles.json(CAP/'domains/metadata/RESULT.json')['rows']) if r['name']=='refuse-hardlink')
control('semantic-binding','split-actual-hardlink-identity',lambda o:o.state('metadata',hard_index,'before',lambda v:next(r for r in v if r['path_base64']=='b3RoZXI=')['identity'].__setitem__(1,1)),['actual initial hardlink identities'])
control('semantic-binding','changed-initial-metadata',lambda o:o.state('ordinary',0,'before',lambda v:v[0].update(mode=0o755)),['whole actual initial metadata/content'])
def changed_pred(o):
    o.mutate_json(CAP/'NATIVE-PREDECESSOR.json',lambda p:p.update(new_native_calls=1));o.resign()
control('admission','changed-native-predecessor',changed_pred,['complete previously admitted native predecessor'])
nativeelf=Path(REQUEST['native_build'])/'text-publication.elf'
control('admission','changed-native-elf-bytes',lambda o:flip(o,nativeelf),['retained hash changed','retained bytes/hash changed'])
def extra_source(o):
    o.mutate_json(CAP/'SOURCE-FILES.json',lambda p:p.update({'unreported.py':pin(b'x')}));o.resign()
control('admission','changed-full-source-closure',extra_source,['complete fixed reference source closure'])
def wrong_version(o):
    p=CAP/'processes/rustc-version/stdout';raw=o.get(p).replace(b'rustc 1.95.0 ',b'rustc 1.99.0 ',1);o.put(p,raw)
    o.process('rustc-version',lambda q:q.update(stdout=pin(raw)))
control('admission','changed-recorded-rust-version',wrong_version,['actual fixed Rust compiler version'])
control('admission','retained-source-symlink',lambda o:o.symlinks.add(str(SOURCE/'driver.rs')),['symlink in retained path'])
control('admission','missing-mapped-compiler-binary',lambda o:o.missing.add(str(CAP/'tool-binaries/cargo')),['No such file or directory'])
control('admission','changed-raw-native-receipt',lambda o:flip(o,Path(REQUEST['native_root'])/'domains/ordinary/process/stderr.bin'),['retained bytes/hash changed'])
require(len(rows)==42 and len({r['name'] for r in rows})==42,'exact independent refusal controls')
require({k:sum(r['group']==k for r in rows) for k in {r['group'] for r in rows}}=={k:7 for k in {r['group'] for r in rows}},'six groups of seven physical controls')
again=evidence(**REQUEST);require(encoded(again)==encoded(baseline),'whole unchanged admission before and after controls')
require(PINS=={**{str(p):pin(p.read_bytes()) for d in a.reader for p in d.rglob('*') if p.is_file()},str(Path(__file__)):pin(Path(__file__).read_bytes())},'all executed source bytes unchanged')
result={'schema':'hepta.runtime.text-publication-original-refusals.v1','status':'PASS','groups':6,'controls':42,
'new_original_processes':0,'new_native_calls':0,'baseline':basepin,'source':PINS,'rows':rows,
'elapsed_seconds':(time.monotonic_ns()-START)/1e9,'unchanged_whole_evidence_after_controls':True}
save(OUT/'RESULT.json',result)
print(json.dumps({k:v for k,v in result.items() if k not in ('source','rows')},sort_keys=True),flush=True)
