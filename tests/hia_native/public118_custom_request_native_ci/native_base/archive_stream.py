"""Read every byte and mode in a fixed complete capture; optionally retain a subset.

The verify path only reads. The extraction path is confined to a new directory
and never executes archive members or follows links.
"""
from pathlib import Path,PurePosixPath
import hashlib,json,os,stat,tarfile,zipfile
def require(ok,text):
    if not ok:raise ValueError(text)
def pin(path):
    path=Path(path)
    with path.open('rb') as f:h=hashlib.file_digest(f,'sha256').hexdigest()
    return {'bytes':path.stat().st_size,'sha256':h}
def safe(name):
    p=PurePosixPath(name)
    require(name and not p.is_absolute() and p.as_posix()==name and all(x not in ('','.','..') for x in p.parts),'archive path')
class Hashing:
    def __init__(self,stream):self.stream=stream;self.digest=hashlib.sha256();self.count=0
    def read(self,n=-1):
        b=self.stream.read(n);self.digest.update(b);self.count+=len(b);return b
    def pin(self):return {'bytes':self.count,'sha256':self.digest.hexdigest()}
def archive(path,identity,choose,*,output=None,verify_root=None):
    path=Path(path);require(pin(path)=={k:identity[k] for k in ('bytes','sha256')},'complete ZIP identity')
    require(output is None or verify_root is None,'one archive selection mode')
    if output is not None:
        output=Path(output);require(not output.exists(),'archive output already exists');output.mkdir(parents=True)
    seen=set();selected={};expected=None
    with zipfile.ZipFile(path) as z:
        require(z.namelist()==['archive.json','capture.tar.gz'],'complete outer ZIP member set')
        for info in z.infolist():require(not info.is_dir() and not stat.S_ISLNK(info.external_attr>>16),'outer ZIP regular members')
        receipt=json.loads(z.read('archive.json'))
        require(receipt['git_head']==identity['source'] and receipt['run_id']==str(identity['run']),'actual producer identity')
        with z.open('capture.tar.gz') as raw:
            hashed=Hashing(raw)
            with tarfile.open(fileobj=hashed,mode='r|gz') as tar:
                for member in tar:
                    require(member.name.startswith('capture/'),'capture archive prefix');name=member.name[8:];safe(name)
                    require(member.isfile() and not member.issym() and not member.islnk() and name not in seen,'unique regular member')
                    src=tar.extractfile(member);require(src is not None,'complete member data');take=choose(name) or name=='artifact-manifest.json';dst=None
                    if expected is None:
                        require(name=='artifact-manifest.json' and member.mode==0o600,'first complete manifest')
                        data=src.read();actual={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()};require(actual==receipt['manifest'],'manifest bytes')
                        manifest=json.loads(data);expected=dict(manifest['files']);require(name not in expected,'manifest cannot list itself');expected[name]={**actual,'mode':0o600}
                        require(manifest['schema']=='hepta.runtime.complete-ci-archive.v2','archive schema')
                        for rel,row in expected.items():
                            safe(rel);require(set(row)=={'bytes','sha256','mode'} and type(row['bytes']) is int and row['bytes']>=0 and type(row['mode']) is int and 0<=row['mode']<=0o777,'manifest complete row')
                        for rel,mode in manifest['directories'].items():safe(rel);require(type(mode) is int and 0<=mode<=0o777,'directory mode')
                        if output is not None:(output/name).write_bytes(data);os.chmod(output/name,member.mode)
                    else:
                        require(name in expected,'unexpected member');digest=hashlib.sha256();size=0
                        if take and output is not None:
                            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);dst=target.open('xb')
                        try:
                            with src:
                                while block:=src.read(1<<20):
                                    digest.update(block);size+=len(block)
                                    if dst is not None:dst.write(block)
                        finally:
                            if dst is not None:dst.close();os.chmod(output/name,member.mode)
                        actual={'bytes':size,'sha256':digest.hexdigest()}
                    require(actual=={k:expected[name][k] for k in ('bytes','sha256')} and member.size==expected[name]['bytes'] and member.mode==expected[name]['mode'],'full member bytes/mode: '+name)
                    if take:
                        selected[name]=expected[name]
                        if verify_root is not None:
                            local=Path(verify_root)/name;require(stat.S_ISREG(local.lstat().st_mode) and not local.is_symlink() and pin(local)==actual and stat.S_IMODE(local.stat().st_mode)==member.mode,'selected byte/mode equality: '+name)
                    seen.add(name)
            while hashed.read(1<<20):pass
            require(hashed.pin()==receipt['archive'],'complete compressed TAR bytes')
        require(seen==set(expected) and receipt['readback']=={'files':len(seen),'logical_bytes':sum(r['bytes'] for r in expected.values())},'complete member set')
    report={'status':'COMPLETE_RETAINED_ARCHIVE_STREAM_READ_PASS','zip':pin(path),'archive_receipt':receipt,'files':len(seen),'selected':selected,'native_or_rust_executions':0}
    if output is not None:(output/'SELECTION.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report
def verify_selection(folder,identity,choose):
    folder=Path(folder);report=json.loads((folder/'SELECTION.json').read_bytes());receipt=report['archive_receipt'];manifest=json.loads((folder/'artifact-manifest.json').read_bytes())
    require(report['status']=='COMPLETE_RETAINED_ARCHIVE_STREAM_READ_PASS' and report['zip']=={k:identity[k] for k in ('bytes','sha256')} and report['native_or_rust_executions']==0,'complete selection identity')
    require(pin(folder/'artifact-manifest.json')==receipt['manifest'] and receipt['git_head']==identity['source'] and receipt['run_id']==str(identity['run']),'manifest producer identity')
    rows=dict(manifest['files']);rows['artifact-manifest.json']={**receipt['manifest'],'mode':0o600};selected={n:r for n,r in rows.items() if choose(n) or n=='artifact-manifest.json'}
    require(report['files']==len(rows) and report['selected']==selected,'exact selected inventory')
    require({p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}==set(selected)|{'SELECTION.json'},'selected closure')
    for name,row in selected.items():
        path=folder/name;require(stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink() and pin(path)=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE(path.stat().st_mode)==row['mode'],'complete selected member: '+name)
    return report
