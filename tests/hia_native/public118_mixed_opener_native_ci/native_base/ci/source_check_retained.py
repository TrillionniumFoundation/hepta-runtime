"""Admit every frozen reference source byte and the complete reader inverses."""
from pathlib import Path
import argparse,hashlib,json,stat,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import pin,require,verify
def git_blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def source(package,manifest_sha256,syntax=False):
    package=Path(package).resolve(strict=True);manifest=package/'PACKAGE.json'
    require(pin(manifest)['sha256']==manifest_sha256,'complete frozen reference package identity')
    data=json.loads(manifest.read_bytes());expected=dict(data['files']);expected['PACKAGE.json']=pin(manifest)
    actual=verify(package,expected)
    for n,row in data['files'].items():
        path=package/n;require(path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode),'unaliased source '+n)
        require(git_blob(path.read_bytes())==row['git_blob'] and bool(path.stat().st_mode&0o111)==(row['mode']=='100755'),'complete source identity '+n)
        if syntax and n.endswith('.py'):compile(path.read_bytes(),str(path),'exec',dont_inherit=True)
    adapters=json.loads((package/'ci/ADAPTERS.json').read_bytes())
    for name,row in adapters['files'].items():
        before=(package/row['original']).read_bytes();after=(package/name).read_bytes()
        require(pin(package/row['original'])=={k:row['before'][k] for k in ('bytes','sha256')} and git_blob(before)==row['before']['git_blob'],'complete prior reader source')
        require(pin(package/name)=={k:row['after'][k] for k in ('bytes','sha256')} and git_blob(after)==row['after']['git_blob'],'complete current reader source')
        restored=after.decode()
        for c in reversed(row['changes']):
            require(restored.count(c['after'])==c['count'],'reader inverse count '+name)
            restored=restored.replace(c['after'],c['before'])
        require(restored.encode()==before,'complete reference reader inverse '+name)
    return {'status':'EXACT_REFERENCE_SOURCE_CLOSURE_PASS','files':len(actual),'manifest':pin(manifest),'reader_adapters':len(adapters['files']),'native_or_rust_executed':False}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--manifest-sha256',required=True);a=p.parse_args()
    print(json.dumps(source(a.package,a.manifest_sha256,True),sort_keys=True))
