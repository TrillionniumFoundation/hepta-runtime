"""Guard the entire original archive, then split its unchanged bytes for transfer."""
from pathlib import Path
import argparse,codecs,gzip,hashlib,json,os,shutil,sys,traceback,zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import verify_archive as reader
import read_only_guard as guard
CHUNK=384<<20
def put(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n')
def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    out=a.output.resolve();assert not out.exists();proof=out/'proof';proof.mkdir(parents=True)
    try:
        assert reader.pin(ROOT/'PROFILE.json')['sha256']==a.profile
        profile=json.loads((ROOT/'PROFILE.json').read_bytes())
        assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(profile['files'])|{'PROFILE.json'}
        for n,row in profile['files'].items():assert reader.pin(ROOT/n)==row
        for n in ('utf-8','utf-8-sig','ascii','cp437'):codecs.lookup(n)
        assert gzip.decompress(gzip.compress(b'',mtime=0))==b''
        with zipfile.ZipFile(a.input) as z:assert len(z.infolist())==2
        result=guard.guarded(lambda:reader.verify(a.input),roots=[ROOT,a.input.resolve(strict=True).parent],foreign_path=Path('/dev/null'))
        assert result['before']==result['after'] and len(result['probes'])==11 and result['native_or_rust_executions']==result['reader_writes']==0
        put(proof/'READONLY.json',result)
        for n,row in result['evidence']['selected'].items():
            dst=proof/'selected'/n;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(bytes.fromhex(row['hex']));dst.chmod(row['mode'])
        shutil.copytree(ROOT,proof/'reader-source')
        parts=[];whole=hashlib.sha256();count=0
        with a.input.open('rb') as src:
            for index in range(2):
                folder=out/('part-'+str(index));folder.mkdir();path=folder/'part.bin';remaining=min(CHUNK,reader.ZIP['bytes']-count)
                with path.open('xb') as dst:
                    while remaining:
                        b=src.read(min(1<<20,remaining));assert b;dst.write(b);whole.update(b);remaining-=len(b);count+=len(b)
                parts.append({'index':index,**reader.pin(path)})
            assert src.read(1)==b'' and {'bytes':count,'sha256':whole.hexdigest()}==reader.ZIP
        transport={'schema':'hepta.runtime.complete-artifact-chunks.v1','status':'COMPLETE_UNCHANGED_ZIP_SPLIT_PASS','original_artifact':14286335670,'original_run':43986339038,'original_source':'4bbc2bf893f9b8248a9f5eb581b422297aba018a','original_zip':reader.ZIP,'parts':parts,'chunk_size':CHUNK,'archive_readback':reader.pin(proof/'READONLY.json'),'source_profile_sha256':a.profile,'native_or_rust_executed':False,'qualified_semantics_replayed':False}
        put(proof/'TRANSPORT.json',transport)
        for row in parts:put(out/('part-'+str(row['index']))/'TRANSPORT.json',transport)
        print(json.dumps(transport,sort_keys=True))
    except BaseException as error:
        put(proof/'FAILURE.json',{'status':'FAIL','error':repr(error),'traceback':traceback.format_exc(),'native_or_rust_executed':False});raise
if __name__=='__main__':main()
