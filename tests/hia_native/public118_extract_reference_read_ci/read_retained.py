"""Read the same successful reference build using one admitted source-loader fix."""
from pathlib import Path
import argparse,hashlib,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
def pin(p):
    raw=Path(p).read_bytes();return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def admit(profile):
    assert pin(ROOT/'PROFILE.json')['sha256']==profile
    data=json.loads((ROOT/'PROFILE.json').read_bytes())
    assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(data['files'])|{'PROFILE.json'}
    for n,row in data['files'].items():assert pin(ROOT/n)==row,n
    return data
def main():
    p=argparse.ArgumentParser();p.add_argument('--capture',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args();admit(a.profile)
    capture=a.capture.resolve(strict=True);package=capture/'ci-package';sys.path[:0]=[str(package/'ci'),str(package/'reference')]
    import read_gate
    read_gate.source(package,'fec98075c21e5761ae344d786d457144c5fb01aa48ab7427bb65748b26ea9e22')
    proof=json.loads((ROOT/'LOADER_CHANGE.json').read_bytes());original=package/'reference/authoring/author_public_reference.py'
    assert pin(original)==proof['before'] and pin(ROOT/'readonly_author.py')==proof['after']
    old=original.read_bytes();new=(ROOT/'readonly_author.py').read_bytes();s=proof['substitution'];assert old.count(s['before'].encode())==s['count']==1 and old.replace(s['before'].encode(),s['after'].encode())==new
    base_loader=read_gate.read_reference.source_module
    def admitted_loader(name,path):
        path=Path(path)
        if path.resolve(strict=True)==original:
            assert pin(path)==proof['before'] and pin(ROOT/'readonly_author.py')==proof['after']
            module=base_loader(name,ROOT/'readonly_author.py');module.ROOT=package/'reference';return module
        return base_loader(name,path)
    read_gate.read_reference.source_module=admitted_loader
    read_gate.prepare(package)
    def verify():
        admit(a.profile)
        result=read_gate.verify(package,capture,'fec98075c21e5761ae344d786d457144c5fb01aa48ab7427bb65748b26ea9e22')
        return {'status':'RETAINED_EXTRACT_REFERENCE_COMPLETE_READ_PASS','qualification':result,'loader_adaptation':proof,'producer_conclusion_retained':'FAIL','native_or_rust_executed':False,'successful_semantics_replayed':False,'captured_reference_source_mutated':False}
    report=read_gate.read_only_guard.guarded(verify,roots=[ROOT,capture],foreign_path=Path('/dev/null'))
    assert report['before']==report['after'] and len(report['probes'])==11 and report['reader_writes']==report['native_or_rust_executions']==0
    print(json.dumps(report,sort_keys=True,allow_nan=False))
if __name__=='__main__':main()
