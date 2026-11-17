"""Verify every retained archive byte and select existing executables; never build or run."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,shutil,tarfile,zipfile
PINS={
 'native':{'artifact':14286335670,'run':43986339038,'source':'4bbc2bf893f9b8248a9f5eb581b422297aba018a','bytes':772760570,'sha256':'71a001f1e57719182a52e9a9025e87999052ac12e879c65f9077fafd42e4b702'},
 'original':{'artifact':14286891582,'run':43988628108,'source':'c61d58a998936e7b6c383a4eb22e97b7ef002886','bytes':483684477,'sha256':'f48324b3842de7654c1cd220e895be824688961a592d590f9aeaba1a49bf5fda'},
 'native-proof':{'artifact':14286667331,'run':43989053606,'source':'39d10cf71b21fce7a6f2990466befbdb181403f1','bytes':6114738,'sha256':'2c9d363a0e288da705ec4a29fb1597f9aff7e63a57e104501c6c8c95a6ce78ce'},
 'original-proof':{'artifact':14288241064,'run':43990818876,'source':'d72d74be71fbe03f40fa10c7116c4f293ec5e85a','bytes':4603342,'sha256':'498caa4ced5944aae5bb2178cb5bc4ad35957c963e87921fb7a5488ea4b159ad'}}
BINARIES={
 'native-private':{'source':'native','path':'instances/task-pump/filesystem-fixture.elf','bytes':24793088,'sha256':'97b420b0407e554f55ca0ebc6d61c118915b56acc5c0e02064142b37632054ac'},
 'native-public':{'source':'native','path':'production/build/public-task-batch-extract/runtime-mcp.elf','bytes':24801280,'sha256':'8c69115ba1b4e768470cf97524edd37093627f273644689424580d283baa9d8c'},
 'original':{'source':'original','path':'original/bin/hepta-batch-sdk-current-original-oracle','bytes':5659800,'sha256':'d2aed5b286630dd67d2d1fc2b15b080598d5f8d3bd520f6c392b9001a633deb3'}}
def pin_file(path):
    h=hashlib.sha256();size=0
    with Path(path).open('rb') as f:
        while b:=f.read(1<<20):h.update(b);size+=len(b)
    return {'bytes':size,'sha256':h.hexdigest()}
def safe(name):
    p=PurePosixPath(name);assert name and not p.is_absolute() and p.as_posix()==name and all(x not in ('','.','..') for x in p.parts);return p
def selected(role,name):
    binaries={row['path'] for row in BINARIES.values() if row['source']==role}
    if name in binaries or name=='artifact-manifest.json':return True
    if role=='original':return name.startswith('ci-package/') or name in ('original/BUILD.json','CORE_READY.json','FAILURE.json','reader-controls/report.json','CI_SOURCE_DECLARATION.json')
    return name.startswith('ci-package/graph/source/') or name in ('ci-package/PACKAGE.json','BUILD_PASS.json','BUILD_ORIGIN.json','production/BUILD.json','production/build/public-task-batch-extract/manifest.json','instances/task-pump/manifest.json','reader-controls/report.json','CI_SOURCE_DECLARATION.json')
class Hashing:
    def __init__(self,stream):self.stream=stream;self.h=hashlib.sha256();self.n=0
    def read(self,n=-1):
        b=self.stream.read(n);self.h.update(b);self.n+=len(b);return b
    def pin(self):return {'bytes':self.n,'sha256':self.h.hexdigest()}
def archive(role,path,output):
    with zipfile.ZipFile(path) as z:
        assert z.namelist()==['archive.json','capture.tar.gz'] and z.testzip() is None
        receipt=json.loads(z.read('archive.json'));assert receipt['git_head']==PINS[role]['source'] and receipt['run_id']==str(PINS[role]['run'])
        expected=None;seen=set();chosen={}
        with z.open('capture.tar.gz') as raw:
            stream=Hashing(raw)
            with tarfile.open(fileobj=stream,mode='r|gz') as tar:
                for member in tar:
                    assert member.name.startswith('capture/');name=member.name[8:];safe(name);assert member.isfile() and not member.issym() and not member.islnk() and name not in seen
                    src=tar.extractfile(member);assert src is not None
                    if expected is None:
                        assert name=='artifact-manifest.json' and member.mode==0o600;data=src.read();manifest=json.loads(data)
                        assert {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}==receipt['manifest'];expected=dict(manifest['files']);expected[name]={**receipt['manifest'],'mode':0o600}
                        for rel in expected:safe(rel)
                        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);os.chmod(target,member.mode);chosen[name]=expected[name]
                    else:
                        assert name in expected;row=expected[name];assert member.size==row['bytes'] and member.mode==row['mode'];h=hashlib.sha256();n=0;dst=None
                        if selected(role,name):
                            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);dst=target.open('xb')
                        try:
                            with src:
                                while b:=src.read(1<<20):
                                    h.update(b);n+=len(b)
                                    if dst is not None:dst.write(b)
                        finally:
                            if dst is not None:dst.close();os.chmod(target,member.mode)
                        assert {'bytes':n,'sha256':h.hexdigest()}=={k:row[k] for k in ('bytes','sha256')},name
                        if dst is not None:chosen[name]=row
                    seen.add(name)
            while stream.read(1<<20):pass
            assert stream.pin()==receipt['archive']
        assert seen==set(expected) and receipt['readback']=={'files':len(seen),'logical_bytes':sum(x['bytes'] for x in expected.values())}
    report={'status':'COMPLETE_RETAINED_ARCHIVE_STREAM_READ_PASS','zip':pin_file(path),'archive_receipt':receipt,'files':len(seen),'selected':chosen,'native_or_rust_executions':0}
    (output/'SELECTION.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');return report
def proof(role,path,output):
    with zipfile.ZipFile(path) as z:
        assert z.testzip() is None;seen=set()
        for item in z.infolist():
            safe(item.filename);assert item.filename not in seen and not item.is_dir();seen.add(item.filename);target=output/item.filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(item.filename))
    candidate=list(output.rglob('READONLY.json')) if role=='native-proof' else list(output.rglob('extract-reference-retained-read.stdout'));assert len(candidate)==1
    value=json.loads(candidate[0].read_bytes());assert value['before']==value['after'] and len(value['probes'])==11 and value['reader_writes']==value['native_or_rust_executions']==0 and value['source_bound_guard'] is True
    evidence=value['evidence']
    if role=='native-proof':assert evidence['status']=='COMPLETE_PUBLIC118_ARCHIVE_STREAM_READ_PASS' and evidence['artifact']==14286335670 and evidence['zip']=={k:PINS['native'][k] for k in ('bytes','sha256')}
    else:
        assert evidence['status']=='RETAINED_EXTRACT_REFERENCE_COMPLETE_READ_PASS' and evidence['producer_conclusion_retained']=='FAIL' and evidence['successful_semantics_replayed'] is False
        assert evidence['qualification']['controls']['refusals']==4 and evidence['qualification']['original']['fresh_original_build'] is True
    return {'status':'COMPLETE_RETAINED_PROOF_READ_PASS','zip':pin_file(path),'files':len(seen),'guard_probes':11,'native_or_rust_executions':0}
def prepare(input_folder,output):
    input_folder=Path(input_folder);output=Path(output);assert not output.exists();output.mkdir(parents=True);reports={}
    for role,pin in PINS.items():
        path=input_folder/(role+'.zip');assert pin_file(path)=={k:pin[k] for k in ('bytes','sha256')};meta=json.loads((input_folder/(role+'.json')).read_bytes());assert meta['id']==pin['artifact'] and meta['digest']=='sha256:'+pin['sha256'] and meta['workflow_run']['id']==pin['run'] and meta['workflow_run']['head_sha']==pin['source']
        dest=output/role;dest.mkdir();reports[role]=archive(role,path,dest) if role in ('native','original') else proof(role,path,dest);shutil.copy2(input_folder/(role+'.json'),output/(role+'.artifact.json'))
        if role.endswith('-proof'):shutil.copy2(path,output/(role+'.zip'))
    binaries={}
    for name,row in BINARIES.items():
        path=output/row['source']/row['path'];assert pin_file(path)=={k:row[k] for k in ('bytes','sha256')};binaries[name]={'path':str(path.resolve()),**pin_file(path)}
    result={'status':'RETAINED_NATIVE118_AND_ORIGINAL_REFERENCE_READY','binaries':binaries,'archives':{k:{x:v[x] for x in ('status','zip','files','native_or_rust_executions')} for k,v in reports.items()},'native_build_source':PINS['native']['source'],'original_build_source':PINS['original']['source'],'original_producer_conclusion':'FAIL','original_build_read_recovered':True,'runtime_recompiled':False,'runtime_hia_images':118,'physical_images':111,'installed_handlers':10,'native_or_rust_executions':0}
    (output/'READY.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(prepare(a.input,a.output),sort_keys=True))
