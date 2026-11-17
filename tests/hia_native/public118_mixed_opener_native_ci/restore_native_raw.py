"""Admit complete fixed native and original raw captures without replaying originals."""
from pathlib import Path
import json,shutil,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'native_base'))
import restore as native_restore
sys.path.insert(0,str(ROOT))
import archive_stream,read_only_guard,read_stdio
CONFIG=json.loads((ROOT/'RAW_RETAINED.json').read_bytes())
def need(ok,message):
    if not ok:raise ValueError(message)
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def artifact(inputs,name,want):
    meta=json.loads((inputs/(name+'.json')).read_bytes())
    need(meta['id']==want['artifact'] and meta['digest']=='sha256:'+want['sha256'] and meta['workflow_run']['id']==want['run'] and meta['workflow_run']['head_sha']==want['source'],'fixed artifact metadata '+name)
    need(archive_stream.pin(inputs/(name+'.zip'))=={k:want[k] for k in ('bytes','sha256')},'full artifact ZIP '+name);return meta
def prepare(inputs,out,domain):
    inputs,out=Path(inputs),Path(out);out.mkdir(exist_ok=False)
    need(CONFIG['native']==native_restore.CONFIG['native'] and CONFIG['native-proof']==native_restore.CONFIG['native-proof'] and CONFIG['binary']==native_restore.CONFIG['binaries']['native-public'],'same exact native source/build configuration')
    for name,want in (('native',CONFIG['native']),('native-proof',CONFIG['native-proof']),('prior',CONFIG['prior'][domain])):put(out/(name+'.artifact.json'),artifact(inputs,name,want))
    report=archive_stream.archive(inputs/'native.zip',CONFIG['native'],native_restore.native_selected,output=out/'native');put(out/'FULL_NATIVE_ARCHIVE_READ.json',report)
    shutil.copy2(inputs/'native-proof.zip',out/'native-proof.zip');native_restore.proof_extract(out/'native-proof.zip',out/'native-proof')
    proof=native_restore.proof_verify(out/'native-proof.zip',out/'native-proof');put(out/'NATIVE_PROOF_READ.json',proof)
    shutil.copy2(inputs/'prior.zip',out/'prior.zip')
    full=archive_stream.archive(out/'prior.zip',CONFIG['prior'][domain],lambda name:True,output=out/'prior');put(out/'FULL_PRIOR_ARCHIVE_READ.json',full)
    prior=out/'prior';source=prior/'source'
    for name in CONFIG['exact_driver_files']:need((source/name).read_bytes()==(ROOT/name).read_bytes(),'exact original capture/read/input source '+name)
    old=read_stdio.read(prior,source,CONFIG['prior_profile']);need(old==json.loads((prior/'READONLY.json').read_bytes())['evidence'],'complete retained original raw read')
    need(json.loads((prior/'RUN.json').read_bytes())['status']=='COMPLETE_ORIGINAL_RAW_STDIO_DOMAIN_PASS','original raw producer passed')
    binary=out/'native'/CONFIG['binary']['path'];need(archive_stream.pin(binary)=={k:CONFIG['binary'][k] for k in ('bytes','sha256')},'actual public native entry')
    return binary
def verify(out,domain):
    out=Path(out)
    archive_stream.verify_selection(out/'native',CONFIG['native'],native_restore.native_selected)
    native=native_restore.proof_verify(out/'native-proof.zip',out/'native-proof');need(native==json.loads((out/'NATIVE_PROOF_READ.json').read_bytes()),'complete fixed native proof')
    need(archive_stream.pin(out/'native-proof.zip')=={k:CONFIG['native-proof'][k] for k in ('bytes','sha256')},'complete proof ZIP bytes')
    prior=archive_stream.archive(out/'prior.zip',CONFIG['prior'][domain],lambda name:True,verify_root=out/'prior')
    need(prior==json.loads((out/'prior/SELECTION.json').read_bytes()),'every original archive byte and mode')
    source=out/'prior/source'
    for name in CONFIG['exact_driver_files']:need((source/name).read_bytes()==(ROOT/name).read_bytes(),'retained input/capture/read source '+name)
    return {'status':'FULL_NATIVE_AND_ORIGINAL_RAW_CUSTODY_PASS','native_build':CONFIG['native'],'prior':CONFIG['prior'][domain],'native_or_rust_executions':0}
