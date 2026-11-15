"""Physical/re-signed rejection and two-root rereads; zero native execution."""
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,io,json,os,stat,struct,sys,time
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
class Files:
    def __init__(self,maps):self.maps=maps;self.reads=set()
    def mapped(self,name):
        p=Path(name)
        if not p.is_absolute() or '..' in p.parts:raise ValueError('invalid origin')
        matches=[(len(old.parts),old,new) for old,new in self.maps if p==old or p.is_relative_to(old)]
        if not matches:raise ValueError('unmapped origin')
        _,old,new=max(matches)
        return new/p.relative_to(old)
    def raw(self,name):
        p=self.mapped(name);matches=[new for _,new in self.maps if p==new or p.is_relative_to(new)]
        root=max(matches,key=lambda p:len(p.parts));q=root
        if q.is_symlink():raise ValueError('symlinked read root')
        for item in p.relative_to(root).parts:
            q=q/item
            if stat.S_ISLNK(q.lstat().st_mode):raise ValueError('symlinked evidence')
        if not stat.S_ISREG(p.lstat().st_mode):raise ValueError('evidence is not regular')
        self.reads.add(str(p));return p.read_bytes()
def main():
    p=argparse.ArgumentParser()
    for name in ('native-root','packer-root','test-source','helper','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source',type=Path)
    p.add_argument('--python-executable',type=Path,default=Path(sys.executable))
    a=p.parse_args();native=a.native_root.resolve();packing=a.packer_root.resolve()
    source=(a.source or native/'source').resolve();manifest=native/'graph-v1/native/manifest.json';test=a.test_source.resolve()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    helper=load(a.helper.resolve(),'batch_private_qualification')
    original_maps=[(source,source),(native,native),(packing,packing),(test,test)]
    basefiles=Files(original_maps)
    def admit(files):
        return {'state':helper.state_evidence(files,native,source),
                'packing':helper.packer_evidence(files,source,manifest,packing,
                    python_executable=str(a.python_executable),test_source=test)}
    baseline=admit(basefiles)
    (out/'baseline.json').write_bytes(canonical(baseline))
    artifacts={}
    for value in baseline.values():
        for name,digest in value['artifact_sha256'].items():
            if name in artifacts:assert artifacts[name]==digest
            artifacts[name]=digest
    for name,digest in artifacts.items():assert sha(basefiles.raw(name))==digest
    (out/'reader-source.py').write_bytes(a.helper.read_bytes())
    (out/'test-source.py').write_bytes(Path(__file__).read_bytes())
    def snapshot(name):
        folder=out/name;folder.mkdir()
        maps=[(source,folder/'source'),(native,folder/'native'),
              (packing,folder/'packing'),(test,folder/'packing-test.py')]
        files=Files(maps)
        for origin,digest in artifacts.items():
            old=basefiles.mapped(origin);new=files.mapped(origin)
            new.parent.mkdir(parents=True,exist_ok=True)
            os.link(old,new,follow_symlinks=False)
        return folder,files
    def put(files,name,raw):
        path=files.mapped(name);path.unlink();path.write_bytes(raw)
    def json_get(files,path):return json.loads(files.raw(path))
    def json_put(files,path,value):put(files,path,canonical(value))
    def resign_record(files,folder,label,where,offset=0):
        ip=folder/'index.jsonl';gp=folder/'complete.bin.gz'
        rows=[json.loads(line) for line in files.raw(ip).splitlines()]
        old=gzip.GzipFile(fileobj=io.BytesIO(files.raw(gp)),mode='rb')
        target=files.mapped(gp);target.unlink()
        fresh=gzip.GzipFile(filename=str(target),mode='wb',mtime=0,compresslevel=1)
        seen=False
        for row in rows:
            raw=bytearray(old.read(row['bytes']));assert len(raw)==row['bytes']
            _,_,ilen,ocap,wcap,_,_,_=struct.unpack_from('<8Q',raw)
            if row['label']==label:
                seen=True
                locations={'input':64,'output':64+ilen+ocap+wcap,
                           'workspace':64+ilen+2*ocap+wcap}
                at=locations[where]+offset
                assert 0<=at<len(raw);raw[at]^=1
                row['sha256']=sha(raw)
            fresh.write(raw)
        assert seen and old.read()==b''
        fresh.close();old.close()
        put(files,ip,b''.join(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n' for row in rows))
    controls=[]
    def reject(name,mutate):
        folder,files=snapshot(name);mutate(files)
        started=time.monotonic_ns();error=None
        try:admit(files)
        except (ValueError,KeyError,TypeError,FileNotFoundError) as exc:error={'type':type(exc).__name__,'message':str(exc)}
        result={'name':name,'rejected':error is not None,'error':error,
                'elapsed_seconds':(time.monotonic_ns()-started)/1e9,
                'input_files':{str(path.relative_to(folder)):sha(path.read_bytes())
                    for path in sorted(folder.rglob('*')) if path.is_file()}}
        controls.append(result)
        (out/(name+'.result.json')).write_bytes(canonical(result))
        assert error is not None,name
    state=native/'state-controls';pack=packing/'capture'
    reject('state-output-resigned',lambda f:resign_record(f,state,'dirty-install-0','output'))
    reject('state-workspace-resigned',lambda f:resign_record(f,state,'corrupt-saved-delivery','workspace',464))
    reject('state-growth-resigned',lambda f:resign_record(f,state,'growth-work','output',48))
    def missing(files):
        name=state/'index.jsonl';rows=files.raw(name).splitlines()
        put(files,name,b'\n'.join(rows[:-1])+b'\n')
    reject('state-missing-record',missing)
    def duplicate(files):
        name=state/'index.jsonl';rows=files.raw(name).splitlines();rows[1]=rows[0]
        put(files,name,b'\n'.join(rows)+b'\n')
    reject('state-duplicate-record',duplicate)
    reject('state-input-resigned',lambda f:resign_record(f,state,'dirty-install-0','input'))
    reject('packer-output-resigned',lambda f:resign_record(f,pack,'exact','output'))
    reject('packer-workspace-resigned',lambda f:resign_record(f,pack,'changed-prefix','workspace'))
    def undo_contract(files):
        name='scripts/batch_call_fixture.S';original=files.raw(source/name)
        path=pack/'contracts/assembly-source'/name;put(files,path,original)
        summary=json_get(files,pack/'contracts.json')
        row=next(row for row in summary['controls'] if row['label']=='assembly-source')
        row['source_pins'][name]={'bytes':len(original),'sha256':sha(original)}
        json_put(files,pack/'contracts.json',summary)
    reject('contract-not-physically-mutated',undo_contract)
    def process_field(files,key,value):
        row=json_get(files,packing/'PROCESS.json');row[key]=value
        json_put(files,packing/'PROCESS.json',row)
        terminal=json_get(files,packing/'RESULT.json');terminal['process']=row
        json_put(files,packing/'RESULT.json',terminal)
    reject('actual-process-timeout',lambda f:process_field(f,'timed_out',True))
    reject('actual-process-boolean-exit',lambda f:process_field(f,'exit_code',False))
    def summary_count(files):
        value=json_get(files,pack/'RESULT.json');value['native_packer_calls']=15
        json_put(files,pack/'RESULT.json',value)
        raw=canonical(value);put(files,packing/'stdout',raw)
        row=json_get(files,packing/'PROCESS.json')
        row['stdout']={'bytes':len(raw),'sha256':sha(raw)}
        json_put(files,packing/'PROCESS.json',row)
        terminal=json_get(files,packing/'RESULT.json');terminal['process']=row
        json_put(files,packing/'RESULT.json',terminal)
    reject('re-signed-false-summary',summary_count)
    first,relocated=snapshot('relocation-first')
    assert admit(relocated)==baseline
    assert all(Path(path).is_relative_to(first) for path in relocated.reads)
    second=out/'relocation-second'
    first.rename(second);assert not first.exists()
    relocated2=Files([(old,second/new.relative_to(first)) for old,new in relocated.maps])
    assert admit(relocated2)==baseline
    assert all(Path(path).is_relative_to(second) for path in relocated2.reads)
    for name,digest in artifacts.items():assert sha(basefiles.raw(name))==digest
    result={'status':'PASS','test_groups':4,'refusals':12,'mapped_root_rereads':2,
            'first_snapshot_source_and_output_absent':True,'all_reads_use_explicit_new_roots':True,
            'native_and_original_fixture_reads':0,'baseline_artifacts':len(artifacts),
            'baseline_evidence_sha256':sha(canonical(baseline)),
            'reader_sha256':sha(a.helper.read_bytes()),'test_sha256':sha(Path(__file__).read_bytes()),
            'new_native_calls':0,'new_original_rust_processes':0}
    (out/'result.json').write_bytes(canonical(result))
    print(json.dumps(result,sort_keys=True),flush=True)
if __name__=='__main__':main()
