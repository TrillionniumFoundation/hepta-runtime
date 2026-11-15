"""Physical rejection controls and two complete offline relocations; no HIA/Rust execution."""
from pathlib import Path
import argparse,copy,gzip,importlib.util,json,os,signal,struct,subprocess,sys,time,unittest
sys.dont_write_bytecode=True
A=None;R=None;OUT=None;CONTROLS=[];PROCESSES=[]
def replace(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True);temp=path.with_name(path.name+'.new')
    with temp.open('xb')as stream:stream.write(raw)
    os.replace(temp,path)
def write(path,value):replace(path,json.dumps(value,sort_keys=True,indent=2,allow_nan=False).encode()+b'\n')
def case(name):
    folder=OUT/'controls'/name;folder.mkdir(parents=True);return folder
def rejected(name,callback,files=()):
    try:callback()
    except (ValueError,AssertionError)as error:
        CONTROLS.append({'name':name,'status':'REJECTED','error':str(error),
            'files':{str(p.relative_to(OUT)):R.file_pin(p)for p in files}})
        write(OUT/'controls.json',CONTROLS);return
    raise AssertionError('corrupted evidence was admitted: '+name)
def json_control(name,value,callback):
    folder=case(name);path=folder/'changed.json';write(path,value)
    rejected(name,lambda:callback(R.strict_json(path.read_bytes())),[path])
def link_artifacts(root,baseline,keys):
    roots={key:root/key for key in keys}
    for name in baseline['artifact_sha256']:
        key,relative=name.split('/',1)
        if key not in roots:continue
        source=R.inside(Path(A.roots_data[key]),relative);target=roots[key]/relative
        target.parent.mkdir(parents=True,exist_ok=True);os.link(source,target)
    return roots
def parse_state_capture():
    rows=[R.strict_json(x)for x in (Path(A.roots_data['capture'])/'state/calls.jsonl').read_bytes().split(b'\n')if x]
    wanted={'malformed-json-0','fs-next-effect-sequence-overflow','fs-completed-open-work-growth',
            'owner-resume-completed-read-once','validation-error-output-growth'}
    selected={};context={}
    with gzip.open(Path(A.roots_data['capture'])/'state/buffers.bin.gz','rb')as stream:
        for row,expected in zip(rows,R.state_declarations(),strict=True):
            header=R.exact(stream,72);values=struct.unpack_from('<8Q',header,8);parts=[R.exact(stream,n)for n in values[2:]]
            if row['label']in wanted:selected[row['label']]=(copy.copy(row),parts,copy.copy(context),expected)
            R.state_record(row,parts,expected,context)
        R.need(stream.read(1)==b'','whole actual state source EOF')
    return selected
def physical_state(name,source,mutator):
    row,parts,context,expected=source;parts=list(parts);mutator(parts)
    raw=b'HRCST002'+R.pack(row['sequence'],row['code'],*[len(p)for p in parts])+b''.join(parts)
    row=copy.deepcopy(row);row.update(offset=0,bytes=len(raw),sha256=R.sha(raw),parts=[R.bytes_pin(p)for p in parts])
    folder=case(name);path=folder/'buffers.bin.gz';replace(path,gzip.compress(raw,compresslevel=1,mtime=0));write(folder/'index.json',row)
    def check():
        record=gzip.decompress(path.read_bytes());head=record[:72];nums=struct.unpack_from('<8Q',head,8);at=72;observed=[]
        for size in nums[2:]:observed.append(record[at:at+size]);at+=size
        R.need(at==len(record),'complete physical state record')
        index=R.strict_json((folder/'index.json').read_bytes())
        R.same(index['sha256'],R.sha(record),'resigned full state record')
        R.same(index['parts'],[R.bytes_pin(p)for p in observed],'resigned full state parts')
        R.state_record(index,observed,expected,copy.copy(context))
    rejected(name,check,[path,folder/'index.json'])
def first_semantic_records():
    rows=[]
    with gzip.open(Path(A.roots_data['capture'])/'semantic/calls.bin.gz','rb')as stream:
        while True:
            head=R.exact(stream,88);v=struct.unpack_from('<10Q',head,8)
            if v[1]!=0:break
            wire,out,footer=[R.exact(stream,n)for n in v[7:]]
            rows.append({'sequence':v[0],'case_id':v[1],'slot':v[2],'depth':v[3],'code':v[4],
                         'workspace_capacity':v[5],'output_capacity':v[6],'wire':wire,'output':out,'footer':footer})
    R.need(len(rows)==4 and rows[-1]['code']<0xffff0000,'actual first semantic transaction')
    return rows
def physical_semantic(name,original,mutator,tail=b''):
    rows=copy.deepcopy(original);mutator(rows);raw=bytearray();indices=[]
    for row in rows:
        wire,output,footer=row['wire'],row['output'],row['footer']
        header=b'HRCALL02'+R.pack(*(row[k]for k in('sequence','case_id','slot','depth','code','workspace_capacity','output_capacity')),len(wire),len(output),len(footer))
        record=header+wire+output+footer
        index={k:row[k]for k in('sequence','case_id','slot','depth','code','workspace_capacity','output_capacity')}
        index.update(offset=len(raw),bytes=len(record),sha256=R.sha(record),input_bytes=len(wire),input_sha256=R.sha(wire),
            output_bytes=len(output),output_sha256=R.sha(output),footer_bytes=len(footer),footer_sha256=R.sha(footer))
        raw.extend(record);indices.append(index)
    raw.extend(tail);folder=case(name);gz=folder/'calls.bin.gz';idx=folder/'calls.jsonl'
    replace(gz,gzip.compress(raw,compresslevel=1,mtime=0));replace(idx,b''.join(R.canonical(x)for x in indices))
    def check():
        reader=R.SemanticCalls(gz,idx)
        code,out=reader.invoke(0,2,original[0]['wire'])
        R.need(code==original[-1]['code']and out==original[-1]['output'],'actual retained original typed complete output')
        reader.close()
    rejected(name,check,[gz,idx])
def actual_reader(name,roots):
    folder=OUT/name;folder.mkdir();write(folder/'roots.json',{k:str(v)for k,v in roots.items()})
    command=[sys.executable,'-I','-B',str(A.reader),'--roots',str(folder/'roots.json'),'--output',str(folder/'EVIDENCE.json')]
    begin=time.monotonic();timed=False
    with (folder/'stdout').open('xb')as stdout,(folder/'stderr').open('xb')as stderr:
        p=subprocess.Popen(command,cwd=folder,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
        try:code=p.wait(timeout=180)
        except subprocess.TimeoutExpired:timed=True;os.killpg(p.pid,signal.SIGKILL);code=p.wait()
    record={'command':command,'cwd':str(folder),'pid':p.pid,'timeout_seconds':180,'timed_out':timed,
            'exit_code':code,'elapsed_seconds':time.monotonic()-begin,'stdout':R.file_pin(folder/'stdout'),'stderr':R.file_pin(folder/'stderr')}
    PROCESSES.append(record);write(OUT/'processes.json',PROCESSES)
    R.need(code==0 and not timed and (folder/'stderr').read_bytes()==b'','actual complete relocated reader')
    return R.strict_json((folder/'EVIDENCE.json').read_bytes())

class Admission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline=R.native_evidence(A.roots_data);write(OUT/'BASELINE.json',cls.baseline)
        cls.e=R.Evidence(A.roots_data);cls.e.built=cls.e.b['build'].json('result.json');cls.e.b['build'].file('bridge.elf')
    def test_01_typed_json_and_owned_paths(self):
        for name,raw in [('duplicate',b'{"x":1,"x":2}'),('nan',b'{"x":NaN}'),('infinity',b'{"x":Infinity}'),('float-overflow',b'{"x":1e999}')]:
            folder=case('json-'+name);p=folder/'changed.json';replace(p,raw);rejected('json-'+name,lambda p=p:R.strict_json(p.read_bytes()),[p])
        folder=case('paths');replace(folder/'plain',b'x');(folder/'leaf-link').symlink_to('plain');(folder/'dir').mkdir();replace(folder/'dir'/'value',b'y');(folder/'parent-link').symlink_to('dir')
        write(folder/'LINKS.json',{'leaf-link':'plain','parent-link':'dir'})
        for name,path in [('escape','../plain'),('absolute',str(folder/'plain')),('leaf-symlink','leaf-link'),('parent-symlink','parent-link/value')]:
            rejected('path-'+name,lambda path=path:R.inside(folder,path),[folder/'LINKS.json'])
        (folder/'leaf-link').unlink();(folder/'parent-link').unlink()
    def test_02_actual_commands_and_deadlines(self):
        row=copy.deepcopy(self.e.checks[0]);argv=copy.deepcopy(row['command']);cwd=row['cwd']
        edits=[('missing-deadline',lambda x:x.pop('timeout_seconds')),('deadline-bool',lambda x:x.update(timeout_seconds=True)),
            ('missing-timeout',lambda x:x.pop('timed_out')),('startup-error',lambda x:x.update(start_error=None)),
            ('exit-bool',lambda x:x.update(exit_code=False)),('elapsed-zero',lambda x:x.update(elapsed_seconds=0)),
            ('elapsed-too-long',lambda x:x.update(elapsed_seconds=181)),('command-without-isolation',lambda x:x['command'].remove('-I'))]
        for name,edit in edits:
            value=copy.deepcopy(row);edit(value);json_control('process-'+name,value,lambda x:R.process(x,argv,cwd,180))
    def test_03_real_native_compilation_bindings(self):
        folder=Path(A.roots_data['build'])/'build/modules/config-span-config-fs'
        source=(folder/'module.input.bin').read_bytes();image=(folder/'module.image.bin').read_bytes();output=(folder/'module.output.bin').read_bytes()
        receipt=R.strict_json((folder/'module.receipt.json').read_bytes())
        for name,which in [('source-byte','source'),('output-byte','output')]:
            f=case('compile-'+name);s=bytearray(source);o=bytearray(output)
            if which=='source':s[-1]^=1
            else:o[0]^=1
            replace(f/'input.bin',s);replace(f/'output.bin',o);write(f/'receipt.json',receipt)
            rejected('compile-'+name,lambda f=f:R.compile_receipt(R.strict_json((f/'receipt.json').read_bytes()),(f/'input.bin').read_bytes(),image,(f/'output.bin').read_bytes()),[f/'input.bin',f/'output.bin',f/'receipt.json'])
        for name,edit in [('produced-size',lambda x:x.update(produced_bytes=x['produced_bytes']-1)),('input-digest',lambda x:x.update(input_sha256='0'*64)),
                          ('abi-bool',lambda x:x.update(abi_status=False)),('host-compiler',lambda x:x.update(forbidden_compiler_modules_loaded=['hepta.hia_selfhost']))]:
            value=copy.deepcopy(receipt);edit(value);json_control('compile-'+name,value,lambda x:R.compile_receipt(x,source,image,output))
    def test_04_full_semantic_streams(self):
        original=first_semantic_records()
        physical_semantic('semantic-wire',original,lambda rows:rows[0].update(wire=b'X'+rows[0]['wire'][1:]))
        physical_semantic('semantic-sequence',original,lambda rows:rows[0].update(sequence=2))
        physical_semantic('semantic-capacity',original,lambda rows:rows[0].update(workspace_capacity=1))
        physical_semantic('semantic-output',original,lambda rows:rows[-1].update(output=b'X'+rows[-1]['output'][1:]))
        physical_semantic('semantic-footer',original,lambda rows:rows[-1].update(footer=b'x'))
        physical_semantic('semantic-trailing',original,lambda rows:None,tail=b'x')

    def test_05_complete_refusal_and_continuation_buffers(self):
        states=parse_state_capture()
        def flip(parts,index,at):
            raw=bytearray(parts[index]);raw[at]^=1;parts[index]=bytes(raw)
        physical_state('refusal-output',states['malformed-json-0'],lambda p:flip(p,4,0))
        physical_state('refusal-workspace',states['malformed-json-0'],lambda p:flip(p,5,len(p[5])-1))
        physical_state('resource-pending-workspace',states['fs-next-effect-sequence-overflow'],lambda p:flip(p,5,152))
        physical_state('growth-output-tail',states['fs-completed-open-work-growth'],lambda p:flip(p,4,32))
        def payload(parts):
            work=parts[5];footer=len(work)-256;at=R.qword(work,footer+32);size=R.qword(work,footer+40);flip(parts,5,at+size-1)
        physical_state('completed-child-payload',states['owner-resume-completed-read-once'],payload)
        physical_state('completed-regex-ack',states['validation-error-output-growth'],lambda p:flip(p,3,len(p[3])-256+88))
    def test_06_actual_kernel_growth_and_write_binding(self):
        base=Path(A.roots_data['capture'])/'lease'
        stderr=(base/'wide/primary/stderr').read_bytes();kernel=(base/'wide/primary/kernel.trace').read_text()
        for name,at in [('sequence',8),('old-capacity',32)]:
            raw=bytearray(stderr);struct.pack_into('<Q',raw,at,R.qword(raw,at)+1);f=case('kernel-'+name);replace(f/'stderr',raw);replace(f/'trace',kernel.encode())
            rejected('kernel-'+name,lambda f=f:R.growth_receipts(R.parse_receipts((f/'stderr').read_bytes())[0],(f/'trace').read_text()),[f/'stderr',f/'trace'])
        f=case('kernel-missing-resize');changed='\n'.join(line for line in kernel.splitlines()if 'mremap('not in line)+'\n';replace(f/'stderr',stderr);replace(f/'trace',changed.encode())
        rejected('kernel-missing-resize',lambda:R.growth_receipts(R.parse_receipts((f/'stderr').read_bytes())[0],(f/'trace').read_text()),[f/'stderr',f/'trace'])
        f=case('kernel-failed-custody');raw=bytearray((base/'resource/limited/stderr').read_bytes());struct.pack_into('<Q',raw,len(raw)-8,R.qword(raw,len(raw)-8)+4096);replace(f/'stderr',raw);replace(f/'trace',(base/'resource/limited/kernel.trace').read_bytes())
        rejected('kernel-failed-custody',lambda:R.growth_receipts(R.parse_receipts((f/'stderr').read_bytes())[0],(f/'trace').read_text(),True),[f/'stderr',f/'trace'])
        f=case('kernel-stderr-write');replace(f/'stderr',b'X'+stderr[1:]);replace(f/'trace',kernel.encode())
        rejected('kernel-stderr-write',lambda:R.complete_stderr_writes((f/'trace').read_text(),(f/'stderr').read_bytes()),[f/'stderr',f/'trace'])
        rows,_=R.parse_receipts(stderr);out=(base/'wide/primary/stdout').read_bytes();at=0;replies=[]
        while at<len(out):
            h=out[at:at+96];at+=96;n=R.qword(h,24);replies.append((h,out[at:at+n]));at+=n
        f=case('kernel-result-header');raw=bytearray(stderr);raw[-32]^=1;replace(f/'stderr',raw)
        cap=R.growth_receipts(rows,kernel)[1][0]
        rejected('kernel-result-header',lambda:R.lease_trace(R.parse_receipts((f/'stderr').read_bytes())[0],replies,cap),[f/'stderr'])
    def test_07_original_bytes_and_inode_ownership(self):
        original=R.guard_reference(self.e)
        for name,kind in [('input','input.bin'),('output','stdout')]:
            f=case('guard-'+name);copied=link_artifacts(f/'owned',self.baseline,{'capture'})['capture'];path=copied/'guard/group-000'/kind
            raw=bytearray(path.read_bytes());at=(len(raw)-1 if name=='input'else 96+48);raw[at]^=1;replace(path,raw)
            records=R.strict_json((copied/'guard/processes.json').read_bytes());records[0]['stdin'if name=='input'else'stdout']=R.file_pin(path);write(copied/'guard/processes.json',records)
            case_rows=R.strict_json((copied/'guard/group-000/cases.json').read_bytes())
            if name=='input':
                offset=0
                for row in case_rows:
                    n=R.qword(raw,offset+8);wire=raw[offset+16:offset+16+n];row['input_sha256']=R.sha(wire);offset+=16+n
            else:
                offset=0
                for row in case_rows:
                    n=R.qword(raw,offset+24);body=raw[offset+96:offset+96+n];row['full_body_sha256']=R.sha(body);offset+=96+n
            write(copied/'guard/group-000/cases.json',case_rows)
            roots={**A.roots_data,'capture':str(copied)};e=R.Evidence(roots);e.built=self.e.built;e.b['build'].file('bridge.elf')
            rejected('guard-'+name,lambda e=e:R.guard_evidence(e,original),[path,copied/'guard/processes.json',copied/'guard/group-000/cases.json'])
        observations=R.strict_json((Path(A.roots_data['capture'])/'lease/observations.json').read_bytes())
        pids={name:R.strict_json((Path(A.roots_data['capture'])/'lease'/name/'primary/process.json').read_bytes())['native_pid']for name in('ordinary','wide')}
        for name,edit in [('inode',lambda x:x[1]['locks']['controller.lock'].update(inode=x[1]['locks']['controller.lock']['inode']+1)),
                          ('released-still-held',lambda x:x[2]['locks']['controller.lock'].update(locked_by_other=True)),
                          ('descriptor-flags',lambda x:x[1]['fd']['3'].update(fdinfo=x[1]['fd']['3']['fdinfo'].replace('flags:\t','flags:\t7')))]:
            changed=copy.deepcopy(observations);edit(changed)
            json_control('lease-'+name,changed,lambda x:R.lease_observations(x,self.e.old['capture'],pids))
    def test_08_complete_source_and_capture_double_relocation(self):
        folder=OUT/'relocated-a';roots=link_artifacts(folder,self.baseline,set(A.roots_data))
        R.need(set(roots)==set(A.roots_data),'all explicit roots relocated')
        for key,root in roots.items():
            R.need(not (root/'fixtures').exists()and not (root/'guard/group-000/state').exists(),'no live fixture copied')
        result=actual_reader('relocation-a',roots);R.same(result,self.baseline,'complete admission after first relocation')
        new=OUT/'relocated-b';os.rename(folder,new);roots={key:new/key for key in roots}
        result=actual_reader('relocation-b',roots);R.same(result,self.baseline,'complete admission after second relocation')
        write(OUT/'RELOCATION.json',{'complete_equal':True,'roots_moved':len(roots),'actual_reader_processes':2,'live_fixture_copied':False})
def main():
    global A,R,OUT
    p=argparse.ArgumentParser();p.add_argument('--reader',type=Path,required=True);p.add_argument('--roots',type=Path,required=True);p.add_argument('--output',type=Path,required=True);A=p.parse_args();OUT=A.output;OUT.mkdir();started=time.monotonic()
    spec=importlib.util.spec_from_file_location('_strict_config_span',A.reader);R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
    A.roots_data=R.strict_json(A.roots.read_bytes())
    write(OUT/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text()})
    write(OUT/'SOURCE.json',{'reader':{'path':str(A.reader),**R.file_pin(A.reader)},'test':{'path':str(Path(__file__)),**R.file_pin(Path(__file__))},'roots':A.roots_data})
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Admission))
    summary={'schema':'hepta.runtime.config-span-evidence-controls.v1','status':'PASS'if result.wasSuccessful()else'FAIL',
        'tests_run':result.testsRun,'groups':8,'rejected_controls':len(CONTROLS),'actual_relocation_reader_processes':len(PROCESSES),
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'elapsed_seconds':time.monotonic()-started,
        'new_native_calls':0,'new_rust_processes':0}
    write(OUT/'RESULT.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
    if not result.wasSuccessful()or result.testsRun!=8 or len(CONTROLS)!=45 or len(PROCESSES)!=2:raise SystemExit(1)
if __name__=='__main__':main()


