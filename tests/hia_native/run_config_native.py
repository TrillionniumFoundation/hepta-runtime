"""Run the six unchanged native domains and retain their actual completion.

This focused driver does not replace the repository cold/aggregate gates. It
exports the two complete original byte corpora and the real executable paths
needed by the shared original reference recipe.
"""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[2]
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    buildpath=a.build.resolve(strict=True);data=json.loads(buildpath.read_bytes());before=sha(buildpath.read_bytes());out=a.output.resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    modules={n:Path(v['path']) for n,v in data['modules'].items()};binaries={n:Path(v['path']) for n,v in data['executables'].items()}
    for category in ['modules','executables']:
        for record in data[category].values():assert sha(Path(record['path']).read_bytes())==record['sha256']
    suites=[('typed','test_config_json.py',5,['--manifest',modules['json']]),
            ('semantics','test_config_semantics.py',6,sum((['--'+n+'-manifest',modules[n]] for n in ['json','validation','identity']),[])),
            ('fs','test_config_fs.py',8,['--manifest',binaries['fs']]),
            ('owner','test_config_owner.py',7,['--manifest',binaries['owner'],'--fixture-manifest',binaries['fixture']]),
            ('mcp','test_config_mcp.py',5,['--manifest',binaries['mcp'],'--output',out/'mcp']),
            ('receipts','test_config_mcp_receipts.py',4,['--manifest',modules['mcp'],'--output',out/'receipts'])]
    # Snapshot all focused source inputs, including shared helper dependencies.
    inputs={str(path.relative_to(ROOT)):sha(path.read_bytes()) for folder in ['native','scripts','tests/hia_native'] for path in (ROOT/folder).rglob('*') if path.is_file() and '__pycache__' not in path.parts}
    records=[]
    for name,script,groups,args in suites:
        env={k:v for k,v in os.environ.items() if not k.startswith('HIA_')};env['HIA_CONFIG_JSON_CORPUS_DIR']=str(out/'typed-corpus');env['HIA_CONFIG_SEMANTICS_CORPUS_DIR']=str(out/'semantics-corpus')
        command=[sys.executable,str(ROOT/'tests/hia_native'/script),*map(str,args)];start=time.monotonic()
        done=subprocess.run(command,capture_output=True,env=env,timeout=180)
        (out/(name+'.stdout')).write_bytes(done.stdout);(out/(name+'.stderr')).write_bytes(done.stderr)
        if done.returncode:raise AssertionError((name,done.returncode,done.stderr[-4096:]))
        summary=json.loads(done.stdout.decode().splitlines()[-1])
        assert summary['status']=='PASS' and summary.get('test_groups',summary.get('groups'))==groups
        records.append({'name':name,'command':command,'exit':0,'elapsed':time.monotonic()-start,'stdout_sha256':sha(done.stdout),'stderr_sha256':sha(done.stderr),'completed_test_summary':summary})
    for name,want in inputs.items():assert sha((ROOT/name).read_bytes())==want
    assert sha(buildpath.read_bytes())==before
    for category in ['modules','executables']:
        for record in data[category].values():assert sha(Path(record['path']).read_bytes())==record['sha256']
    result={'schema':'hepta.runtime.config-native-tests.v1','status':'PASS','source_unchanged':True,'inputs':inputs,'build_sha256':before,'records':records,
            'modules':data['modules'],'executables':data['executables'],'corpora':{'typed':str(out/'typed-corpus'),'semantics':str(out/'semantics-corpus')},
            'actual_completed_suites':6,'actual_test_groups':35,'complete_config_owner':False,'regex_compilation_closed':False,'fresh_cold_qualified':False}
    (out/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['inputs','records','modules','executables']},sort_keys=True))

if __name__=='__main__':main()
