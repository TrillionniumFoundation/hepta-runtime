"""Complete fixed public118 ZIP/TAR byte reader; no code in the archive is executed."""
from pathlib import Path,PurePosixPath
import hashlib,json,stat,tarfile,zipfile
ZIP={'bytes':772760570,'sha256':'71a001f1e57719182a52e9a9025e87999052ac12e879c65f9077fafd42e4b702'}
PROFILE='de5206f4566cffd483dd1df0e40e172e2892237369cfb84f44e2d47d7ecc4071'
SELECTED={'BUILD_PASS.json','BUILD_ORIGIN.json','production/BUILD.json','reader-controls/report.json','processes/read-build.stdout','processes/physical-controls.stdout','processes/shape-admission-controls.stdout'}
def pin(path):
    with Path(path).open('rb') as f:d=hashlib.file_digest(f,'sha256').hexdigest()
    return {'bytes':Path(path).stat().st_size,'sha256':d}
def safe(n):
    p=PurePosixPath(n);assert n and not p.is_absolute() and '..' not in p.parts and str(p)==n
class HashReader:
    def __init__(self,stream):self.stream=stream;self.digest=hashlib.sha256();self.count=0
    def read(self,n=-1):
        b=self.stream.read(n);self.digest.update(b);self.count+=len(b);return b
    def identity(self):return {'bytes':self.count,'sha256':self.digest.hexdigest()}
def verify(path):
    assert pin(path)==ZIP
    selected={};seen=set();logical=0
    with zipfile.ZipFile(path) as z:
        assert len(z.infolist())==2 and set(z.namelist())=={'capture.tar.gz','archive.json'}
        for i in z.infolist():assert not i.is_dir() and not stat.S_ISLNK(i.external_attr>>16)
        report=json.loads(z.read('archive.json'))
        assert report['source_manifest_sha256']==PROFILE
        with z.open('capture.tar.gz') as stream:
            hashed=HashReader(stream)
            with tarfile.open(fileobj=hashed,mode='r|gz') as tar:
                for m in tar:
                    assert m.name.startswith('capture/');n=m.name[8:];safe(n)
                    assert m.isfile() and not m.issym() and not m.islnk() and n not in seen
                    f=tar.extractfile(m);assert f is not None
                    if not seen:
                        assert n=='artifact-manifest.json' and m.mode==0o600
                        raw=f.read();identity={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()};assert identity==report['manifest']
                        manifest=json.loads(raw);expected=dict(manifest['files']);assert n not in expected;expected[n]={**identity,'mode':0o600}
                        for name,row in expected.items():
                            safe(name);assert set(row)=={'bytes','sha256','mode'} and type(row['bytes']) is int and row['bytes']>=0 and type(row['mode']) is int and 0<=row['mode']<=0o777
                        assert manifest['schema']=='hepta.runtime.complete-ci-archive.v2'
                        for name,mode in manifest['directories'].items():safe(name);assert type(mode) is int and 0<=mode<=0o777
                    else:
                        assert n in expected
                        digest=hashlib.sha256();count=0;chunks=[]
                        while b:=f.read(1<<20):
                            digest.update(b);count+=len(b)
                            if n in SELECTED:chunks.append(b)
                        identity={'bytes':count,'sha256':digest.hexdigest()}
                        assert identity=={k:expected[n][k] for k in ('bytes','sha256')},n
                        if n in SELECTED:selected[n]={'hex':b''.join(chunks).hex(),**identity,'mode':expected[n]['mode']}
                    assert m.size==expected[n]['bytes'] and m.mode==expected[n]['mode'],n
                    seen.add(n);logical+=m.size
            while hashed.read(1<<20):pass
            assert hashed.identity()==report['archive']
        assert seen==set(expected) and report['readback']=={'files':len(seen),'logical_bytes':logical}
        assert set(selected)==SELECTED
    return {'status':'COMPLETE_PUBLIC118_ARCHIVE_STREAM_READ_PASS','source':'4bbc2bf893f9b8248a9f5eb581b422297aba018a','run':43986339038,'artifact':14286335670,'zip':ZIP,'archive_receipt':report,'artifact_manifest':manifest,'files':len(seen),'logical_bytes':logical,'selected':selected,'all_regular_members_read':True,'all_original_modes_checked':True,'native_executed':False,'rust_executed':False,'qualification_inferred_from_archive':False}
