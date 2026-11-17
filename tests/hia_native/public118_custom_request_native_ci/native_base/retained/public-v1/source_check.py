"""Exact source and complete input admission; no HIA/Rust execution."""
from pathlib import Path
import argparse,ast,hashlib,json,stat,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def check(root,profile):
    root=Path(root);raw=(root/'PACKAGE.json').read_bytes();assert hashlib.sha256(raw).hexdigest()==profile;data=json.loads(raw)
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()};assert actual==set(data['files'])|{'PACKAGE.json'}
    for name,row in data['files'].items():
        p=root/name;st=p.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not p.is_symlink() and stat.S_IMODE(st.st_mode)==0o644;assert pin(p.read_bytes())=={k:row[k] for k in ('bytes','sha256','git_blob')},name
    proof=json.loads((root/'READER_ADAPTERS.json').read_bytes());before=(root/'retained/read_public.py').read_bytes();after=(root/'read_public.py').read_bytes();assert pin(before)==proof['before'] and pin(after)==proof['after'];s=after.decode();extra=proof['added_compare_lane'];assert s.count(extra)==1;s=s.replace(extra,'',1)
    for step in reversed(proof['substitutions']):assert s.count(step['after'])==step['count']==1;s=s.replace(step['after'],step['before'])
    assert s.encode()==before
    spec=json.loads((root/'ADAPTERS.initial.json').read_bytes())['changes']['body_fixture.py'];origin=(root/'retained/body_run.py').read_text();generated=(root/'body_fixture.py').read_text();a=ast.parse(origin);b=ast.parse(generated)
    for name in spec['selected_exact_functions']:
        one=next(n for n in a.body if isinstance(n,ast.FunctionDef) and n.name==name);two=next(n for n in b.body if isinstance(n,ast.FunctionDef) and n.name==name)
        assert ast.dump(one,include_attributes=False)==ast.dump(two,include_attributes=False)
        assert ''.join(origin.splitlines(keepends=True)[one.lineno-1:one.end_lineno])==''.join(generated.splitlines(keepends=True)[two.lineno-1:two.end_lineno])
    import public_cases
    inputs=json.loads((root/'INPUTS.json').read_bytes());expected={}
    for domain in public_cases.DOMAINS:
        plans=[public_cases.plan(domain,Path('/FIXTURE'),i) for i in range(153)] if domain.startswith('body-') else [public_cases.plan(domain,Path('/FIXTURE'))]
        encoded=(json.dumps(public_cases.serial(plans),sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode();expected[domain]={'plans':len(plans),'operations':sum(len(p['rows']) for p in plans),'input':pin(encoded)}
    assert inputs['domains']==expected and inputs['runtime_semantics_executed'] is False
    return {'status':'EXACT_PUBLIC_EXTRACT_SOURCE_AND_INPUTS_PASS','files':len(data['files'])+1,'profile':profile,'domains':expected,'native_or_rust_executions':0}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args();sys.path.insert(0,str(a.package));print(json.dumps(check(a.package,a.profile),sort_keys=True))
