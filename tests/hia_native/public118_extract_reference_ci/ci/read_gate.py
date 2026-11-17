"""Whole source/compiler/archive custody and four controls under the unchanged guard."""
from pathlib import Path
import argparse,codecs,gzip,importlib.util,json,sys,tomllib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'reference')]
from common import pin,require
from source_check import source
from receipt_support import check_process
import read_reference,reference_controls,read_only_guard
def prepare(package):
    for enc in ('utf-8','utf-8-sig','ascii'):codecs.lookup(enc)
    require(gzip.decompress(gzip.compress(b'',mtime=0))==b'','gzip source preloading')
    require(tomllib.loads('owned=true')['owned'] is True,'toml source preloading')
    author=read_reference.source_module('extract_reference_preload',package/'reference/authoring/author_public_reference.py')
    generated,proof=author.compose(package/'reference/baseline',package/'reference/core')
    require(proof==json.loads((package/'reference/project/SOURCE.json').read_bytes()),'full original source preflight')
    return proof
def verify(package,capture,profile):
    admitted=source(package,profile)
    original=read_reference.original(capture/'original',package/'reference')
    controls=reference_controls.verify(capture/'original',package/'reference',capture/'reader-controls')
    ready=json.loads((capture/'CORE_READY.json').read_bytes())
    require(ready['status']=='CORE_COMPLETE' and ready['source_manifest_sha256']==profile and ready['source_admission']==admitted,'complete core source admission')
    pref,ps=check_process(capture/'processes','target-prefetch',timeout=180)
    build,bs=check_process(capture/'processes','original-build',timeout=180)
    rust=Path(ready['rust_bin']);producer=Path(ready['capture']);target=Path(ready['target'])
    env={'PYTHONDONTWRITEBYTECODE':'1','LC_ALL':'C','PYTHONPATH':''}
    require(pref['argv']==[str(rust/'cargo'),'fetch','--locked'] and pref['cwd']==str(target) and pref['controlled_env']==env and ps['stdin']==b'','actual independent target prefetch')
    require(build['argv']==[ready['python'],'-I','-S','-B',str(Path(ready['source'])/'reference/build_reference.py'),'--rust-bin',str(rust),'--target',str(target),'--core',str(Path(ready['source'])/'reference/core'),'--output',str(producer/'original')] and build['cwd']==str(producer) and build['controlled_env']==env and bs['stdin']==b'' and bs['stderr']==b'','actual original build invocation')
    report=json.loads((capture/'original/BUILD.json').read_bytes())
    require(json.loads(bs['stdout'])=={k:report[k] for k in ('status','fresh_original_build','binaries','actual_target_sdk','actual_target_tokio','actual_reference_executions')},'complete original build completion stream')
    return {'status':'FRESH_EXTRACT_REFERENCE_COMPLETE_BUILD_READ_PASS','source':admitted,'original':original,'controls':controls,'native_or_rust_executed':False,'reader_writes':0,'public_extract_qualified':False}
def guarded(package,capture,profile):
    package,capture=Path(package).resolve(strict=True),Path(capture).resolve(strict=True)
    prepare(package)
    report=read_only_guard.guarded(lambda:verify(package,capture,profile),roots=[package,capture],foreign_path=Path('/dev/null'))
    require(report['before']==report['after'] and len(report['probes'])==11 and report['reader_writes']==report['native_or_rust_executions']==0,'strict read-only reference closure')
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--capture',type=Path,required=True);p.add_argument('--manifest-sha256',required=True);a=p.parse_args()
    print(json.dumps(guarded(a.package,a.capture,a.manifest_sha256),sort_keys=True,allow_nan=False))
