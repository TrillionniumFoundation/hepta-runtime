"""Derive frozen inputs from frozen source only; no fixture or runtime execution."""
from pathlib import Path
import argparse,hashlib,json,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def main():
    p=argparse.ArgumentParser();p.add_argument('--profile',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    raw=(ROOT/'PACKAGE.json').read_bytes();assert hashlib.sha256(raw).hexdigest()==a.profile;files=json.loads(raw)['files']
    assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(files)|{'PACKAGE.json'}
    for n,r in files.items():assert pin((ROOT/n).read_bytes())=={k:r[k] for k in ('bytes','sha256','git_blob')} and stat.S_IMODE((ROOT/n).stat().st_mode)==0o644
    proof=json.loads((ROOT/'INPUT_CHANGE.json').read_bytes());before=(ROOT/'before_public_cases.py').read_text();after=(ROOT/'public_cases.py').read_text()
    assert before.count(proof['before'])==after.count(proof['after'])==1 and before.replace(proof['before'],proof['after'],1)==after
    import public_cases
    original=json.loads((ROOT/'INPUTS.before.json').read_bytes());expected={}
    for domain in public_cases.DOMAINS:
        plans=[public_cases.plan(domain,Path('/FIXTURE'),i) for i in range(153)] if domain.startswith('body-') else [public_cases.plan(domain,Path('/FIXTURE'))]
        encoded=(json.dumps(public_cases.serial(plans),sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
        expected[domain]={'plans':len(plans),'operations':sum(len(p['rows']) for p in plans),'input':pin(encoded)}
        if not domain.startswith('catalog-'):assert expected[domain]==original['domains'][domain]
    original['domains']=expected;original['runtime_semantics_executed']=False
    out=a.output.resolve();out.mkdir(exist_ok=False);data=(json.dumps(original,sort_keys=True,indent=2)+'\n').encode();(out/'INPUTS.json').write_bytes(data)
    (out/'INPUT_CHANGE.json').write_bytes((ROOT/'INPUT_CHANGE.json').read_bytes())
    report={'status':'VALID_CATALOG_INPUTS_FROZEN_PASS','source_profile':a.profile,'inputs':pin(data),'changed_domains':['catalog-legacy','catalog-modern'],'new_original_input_domain':True,'old_835_original_replayed':False,'native_or_rust_executions':0}
    (out/'RESULT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print('FROZEN_INPUTS_JSON '+json.dumps(data.decode()));print('RESULT '+json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
