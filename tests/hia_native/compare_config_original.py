"""Execute four complete original domains on ai395 or CI with one Cargo build.

The native executables are actual packed HIA images. Rust is only a reference;
it is never invoked by a runtime service. Typed parse failure codes and four
explicit regex dependency refusals have the documented, separate comparison
domains. Every other retained result/error byte is compared exactly.
"""
from pathlib import Path
import argparse,gzip,hashlib,json,os,shutil,subprocess,sys,tempfile,time
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests/hia_native')]
from hia_native_config_reference import prepare_original_reference,check_project
import config_owner_cases as owner
import config_mcp_sessions as mcp

sha=lambda raw:hashlib.sha256(raw).hexdigest()
PENDING=[450,451,452,454]

def checked_corpus(path,cases):
    meta=json.loads((path/'native-corpus.json').read_bytes())
    if meta['cases']!=cases:raise ValueError('native corpus count changed')
    data={}
    for prefix in ['requests','native_output']:
        raw=(path/meta[prefix+'_file']).read_bytes()
        if (len(raw),sha(raw))!=(meta[prefix+'_bytes'],meta[prefix+'_sha256']) or raw.count(b'\n')!=cases:raise ValueError('native corpus changed')
        data[prefix]=raw
    return data,meta

def replay_lines(name,binary,corpus,output,records,environment):
    expected=6491 if name=='typed' else 2063
    raw,metadata=checked_corpus(corpus,expected);started=time.monotonic()
    command=[str(binary)];cwd=Path.cwd()
    done=subprocess.run(command,input=raw['requests'],capture_output=True,env=environment,timeout=180)
    (output/(name+'.stdout.gz')).write_bytes(gzip.compress(done.stdout,mtime=0));(output/(name+'.stderr')).write_bytes(done.stderr)
    record={'name':name,'command':command,'cwd':str(cwd),'request_sha256':sha(raw['requests']),'request_bytes':len(raw['requests']),'exit':done.returncode,'elapsed':time.monotonic()-started,'stdout_sha256':sha(done.stdout),'stdout_bytes':len(done.stdout),'stderr_sha256':sha(done.stderr),'cases':expected,'native_corpus':metadata}
    records.append(record)
    if done.returncode!=0 or done.stdout.count(b'\n')!=expected:raise AssertionError('original replay did not complete: '+name)
    controls={'exact_results':0,'typed_refusals':0,'explicit_regex_dependency':0}
    for index,(native,original) in enumerate(zip(raw['native_output'].splitlines(),done.stdout.splitlines(),strict=True)):
        nc,np=native.split(b':',1);rc,rp=original.split(b':',1)
        if name=='semantics' and index in PENDING:
            assert nc==b'fffffffc' and rc in [b'00000000',b'00000001'];controls['explicit_regex_dependency']+=1
        elif nc==b'ffffffff':
            assert rc==nc and np==b'';controls['typed_refusals']+=1
        elif name=='typed' and nc==b'fffffffd':
            assert rc==nc and np==b'';controls['typed_refusals']+=1
        else:
            assert native==original,(name,index,native[:128],original[:128]);controls['exact_results']+=1
    if name=='semantics':assert metadata['explicit_incomplete_regex_indices']==PENDING and controls['explicit_regex_dependency']==4
    record['comparison']=controls
    return record

def compare_owners(native,fixture,reference,output):
    observations=[];owner.COUNTS.clear()
    with tempfile.TemporaryDirectory(prefix='same-owner-',dir=output) as raw:
        base=Path(raw)
        for index,name in enumerate(owner.FS_CASES+owner.OTHER_CASES):
            root=base/str(index)
            a=owner.run_case(fixture if name.startswith('second-') else native,name,root,True);shutil.rmtree(root)
            b=owner.run_case(reference,name,root,False);shutil.rmtree(root)
            assert a==b,(name,a,b)
            observations.append({'case':name,'native':a,'original':b,'equal':True})
    assert len(observations)==62 and owner.COUNTS['actual_elf_requests']==490
    result={'cases':62,'actual_binary_requests':490,'observations':observations,'same_exact_fixture_paths':True,'native_diagnostic_and_opaque_node_identity_excluded':True}
    (output/'owner-comparison.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return {'cases':62,'actual_binary_requests':490,'report_sha256':sha((output/'owner-comparison.json').read_bytes())}

def compare_mcp(native,reference,output):
    folder=output/'mcp';folder.mkdir()
    with tempfile.TemporaryDirectory(prefix='same-mcp-',dir=folder) as td:
        root=Path(td);config=root/'config';state=root/'state'
        config.write_bytes(mcp.compact({'state_dir':str(state),'hosts':{'h':{'ssh_target':'private-target','remote_state_dir':'/private-state'}}}))
        n=mcp.run(native,config,folder,'native');shutil.rmtree(state);r=mcp.run(reference,config,folder,'original')
    assert len(n['rows'])==len(r['rows'])==1119
    assert n['rows']==r['rows']
    for key in ['requests_sha256','responses_sha256','request_bytes','response_bytes']:assert n[key]==r[key]
    result={'cases':1119,'native':n,'original':r,'actual_sdk_and_installed_owners':True,'same_exact_fixture_paths':True,'actual_protocol_version':'2025-06-18'}
    (folder/'report.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return {'cases':1119,'report_sha256':sha((folder/'report.json').read_bytes()),'requests_sha256':n['requests_sha256'],'responses_sha256':n['responses_sha256']}

def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--native-results',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cargo',type=Path,required=True);p.add_argument('--rustc',type=Path,required=True);p.add_argument('--offline',action='store_true');a=p.parse_args()
    repo=a.repo.resolve(strict=True);result_path=a.native_results.resolve(strict=True);out=a.output.resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    native=json.loads(result_path.read_bytes());assert native['status']=='PASS'
    native_record_sha=sha(result_path.read_bytes());inputs={str(p):sha(p.read_bytes()) for p in [Path(__file__),ROOT/'scripts/hia_native_config_reference.py',*[ROOT/'tests/hia_native'/n for n in ['config_mcp_cases.py','config_mcp_sessions.py','config_fs_cases.py','config_owner_cases.py','config_semantics_cases.py','test_config_fs.py','test_config_owner.py','config_reference_sources.json','config_reference.tar.gz']]]}
    prepared=prepare_original_reference(repo,out/'project');project=out/'project';before=sha((project/'reference-inputs.json').read_bytes());records=[]
    binaries={}
    for name in ['owner','fixture','mcp']:
        manifest=Path(native['executables'][name]['path']);assert sha(manifest.read_bytes())==native['executables'][name]['sha256'];data=json.loads(manifest.read_bytes());binary=manifest.parent/data['executable'];assert sha(binary.read_bytes())==data['elf_sha256'];binaries[name]=binary;inputs[str(manifest)]=sha(manifest.read_bytes());inputs[str(binary)]=data['elf_sha256']
    env={k:v for k,v in os.environ.items() if not k.startswith('HIA_') and k not in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_TARGET_DIR','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC_BOOTSTRAP']}
    env.update(CARGO_NET_OFFLINE='true' if a.offline else 'false',CARGO_TARGET_DIR=str(project/'target'),RUSTC=str(a.rustc.absolute()))
    build_command=[str(a.cargo),'build','--release','--locked','--bins','--manifest-path',str(project/'Cargo.toml')]
    if a.offline:build_command.append('--offline')
    for label,command in [('rust-version',[str(a.rustc),'--version']),('build',build_command)]:
        started=time.monotonic();done=subprocess.run(command,cwd=project,env=env,capture_output=True,timeout=180)
        (out/(label+'.stdout')).write_bytes(done.stdout);(out/(label+'.stderr')).write_bytes(done.stderr)
        records.append({'name':label,'command':command,'exit':done.returncode,'elapsed':time.monotonic()-started,'stdout_sha256':sha(done.stdout),'stderr_sha256':sha(done.stderr)})
        if done.returncode:raise AssertionError((label,done.stderr[-4096:]))
    refs={name:project/'target/release'/('hia-runtime-config-'+name) for name in ['typed','semantics','owner','mcp']}
    refhash={name:sha(path.read_bytes()) for name,path in refs.items()}
    typed=replay_lines('typed',refs['typed'],Path(native['corpora']['typed']),out,records,env)
    semantics=replay_lines('semantics',refs['semantics'],Path(native['corpora']['semantics']),out,records,env)
    installed=compare_owners(binaries['owner'],binaries['fixture'],refs['owner'],out)
    protocol=compare_mcp(binaries['mcp'],refs['mcp'],out)
    check_project(project,prepared)
    assert sha((project/'reference-inputs.json').read_bytes())==before and sha(result_path.read_bytes())==native_record_sha
    assert all(sha(Path(path).read_bytes())==digest for path,digest in inputs.items())
    assert all(sha(path.read_bytes())==refhash[name] for name,path in refs.items())
    # Recheck every original source after the entire execution, without rebuilding.
    for name,want in prepared['original_sources'].items():assert sha((repo/name).read_bytes())==want['sha256']
    report={'schema':'hepta.runtime.config-original-comparison.v1','status':'PASS','source_unchanged':True,'native_result_sha256':native_record_sha,'inputs':inputs,'reference_input_sha256':before,'reference_executables':refhash,'registry_packages':100,'one_shared_cargo_build':True,'records':records,'domains':{'typed':typed,'semantics':semantics,'installed':installed,'mcp':protocol},'total_reference_input_cases':9735,'complete_config_owner':False,'regex_compilation_closed':False,'original_rust_runtime_fallback':False}
    (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ['records','domains','inputs']},sort_keys=True))

if __name__=='__main__':main()
