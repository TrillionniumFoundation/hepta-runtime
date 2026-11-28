"""Five complete native domains versus the locked original crates; ai395/CI only.

The native error classes intentionally omit original parser prose, which is
retained in full. Success projections retain every promised AST/HIR byte,
minimum NFA allocation budget, capture count and Boolean match result.
"""
from pathlib import Path
import argparse,gzip,hashlib,json,os,struct,subprocess,sys,time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_regex_reference import prepare_reference,check_reference,REMOVED_ENV

sha=lambda raw:hashlib.sha256(raw).hexdigest()
DOMAIN_CASES={'unicode':6560,'syntax':18976,'hir':34130,'nfa':3584,'match':65440}


def project_output(domain,raw):
    rows=[]
    for line in raw.splitlines():
        code,body=line.split(b':',1)
        if len(code)!=8 or len(body)%2:raise ValueError('original response framing differs')
        bytes.fromhex(body.decode())
        if code==b'00000001':body=b''
        elif code==b'00000000'and domain in ['nfa','match']:
            length=16 if domain=='nfa'else 32
            if len(body)<length:raise ValueError('truncated original result')
            body=body[:length]
        rows.append(code+b':'+body+b'\n')
    return b''.join(rows)


def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--native-results',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--cargo',type=Path,required=True);p.add_argument('--rustc',type=Path,required=True)
    p.add_argument('--offline',action='store_true');a=p.parse_args()
    repo=a.repo.resolve(strict=True);native_path=a.native_results.resolve(strict=True);native=json.loads(native_path.read_bytes())
    assert native['status']=='PASS'and set(native['corpora'])==set(DOMAIN_CASES)
    output=a.output.resolve();output.mkdir(parents=True,exist_ok=False,mode=0o700)
    project=output/'project';prepared=prepare_reference(repo,project);prepared_hash=sha((project/'reference-inputs.json').read_bytes())
    inputs={str(native_path):sha(native_path.read_bytes()),str(Path(__file__).resolve()):sha(Path(__file__).read_bytes()),
            str(repo/'scripts/hia_native_regex_reference.py'):sha((repo/'scripts/hia_native_regex_reference.py').read_bytes())}
    for relative,digest in native['source_pins'].items():
        path=repo/relative;assert sha(path.read_bytes())==digest;inputs[str(path)]=digest
    env={k:v for k,v in os.environ.items()if not k.startswith('HIA_')and k not in REMOVED_ENV}
    env.update(RUSTC=str(a.rustc.absolute()),CARGO_TARGET_DIR=str(project/'target'),CARGO_NET_OFFLINE='true'if a.offline else'false')
    records=[]
    def run(name,command,wire=None):
        start=time.monotonic();failure=None;timed_out=False;code=None;stdout=stderr=b''
        try:
            r=subprocess.run(command,cwd=project,env=env,input=wire,capture_output=True,timeout=120)
            code=r.returncode;stdout=r.stdout;stderr=r.stderr
        except subprocess.TimeoutExpired as error:
            timed_out=True;stdout=error.stdout or b'';stderr=error.stderr or b'';failure=error
        except OSError as error:failure=error
        outpath=output/(name+'.stdout'+('.gz'if wire is not None else''))
        outpath.write_bytes(gzip.compress(stdout,mtime=0)if wire is not None else stdout)
        (output/(name+'.stderr')).write_bytes(stderr)
        row={'name':name,'command':command,'cwd':str(project),'exit_code':code,'elapsed_seconds':time.monotonic()-start,
             'timeout_seconds':120,'timed_out':timed_out,'start_error':str(failure)if isinstance(failure,OSError)else None,
             'stdout_bytes':len(stdout),'stdout_sha256':sha(stdout),'stderr_bytes':len(stderr),'stderr_sha256':sha(stderr)}
        if wire is not None:row.update(request_bytes=len(wire),request_sha256=sha(wire))
        records.append(row)
        (output/'execution-progress.json').write_text(json.dumps({'status':'FAIL'if failure is not None or code!=0 else'RUNNING','records':records},sort_keys=True,indent=2)+'\n')
        if failure is not None:raise failure
        assert code==0,(name,stderr[-4096:]);return stdout
    version=run('rust-version',[str(a.rustc),'--version'])
    assert version.startswith(b'rustc 1.95.0 '),'capture identifier predicates are pinned to the actual original Rust 1.95 Unicode domain'
    command=[str(a.cargo),'build','--release','--locked','--manifest-path',str(project/'Cargo.toml')]
    if a.offline:command.append('--offline')
    run('cargo-build',command)
    binary=project/'target/release/hia-runtime-regex-reference';binary_hash=sha(binary.read_bytes());domains={}
    for name,count in DOMAIN_CASES.items():
        row=native['corpora'][name];folder=Path(row['directory']).resolve(strict=True)
        request=(folder/'requests.hex').read_bytes();expected=(folder/'native-output.txt').read_bytes()
        assert row['cases']==count and request.count(b'\n')==expected.count(b'\n')==count
        assert(len(request),sha(request))==(row['requests_bytes'],row['requests_sha256'])
        assert(len(expected),sha(expected))==(row['native_output_bytes'],row['native_output_sha256'])
        for filename in ['requests.hex','native-output.txt']:
            path=folder/filename;inputs[str(path)]=sha(path.read_bytes())
        actual=run(name,[str(binary)],request);projected=project_output(name,actual)
        assert actual.count(b'\n')==count and projected==expected,(name,'complete original output differs')
        (output/(name+'.projected.txt.gz')).write_bytes(gzip.compress(projected,mtime=0))
        domains[name]={'cases':count,'request_bytes':len(request),'request_sha256':sha(request),
                       'native_output_bytes':len(expected),'native_output_sha256':sha(expected),
                       'original_output_bytes':len(actual),'original_output_sha256':sha(actual),
                       'projected_bytes':len(projected),'projected_sha256':sha(projected),'complete_stream_compared':True}
    predicate=(Path(native['capture_predicates']['path'])).resolve(strict=True);expected=predicate.read_bytes()
    assert sha(expected)==native['capture_predicates']['sha256'];inputs[str(predicate)]=sha(expected)
    wire=(b'HREGX001'+struct.pack('<3Q',4,0,0)).hex().encode()+b'\n';actual=run('capture-predicates',[str(binary)],wire)
    assert actual==expected and actual.count(b'\n')==1
    check_reference(project,prepared)
    assert sha((project/'reference-inputs.json').read_bytes())==prepared_hash and sha(binary.read_bytes())==binary_hash
    assert all(sha(Path(path).read_bytes())==digest for path,digest in inputs.items())
    report={'schema':'hepta.runtime.regex-original-comparison.v1','status':'PASS','source_unchanged':True,
            'native_result_sha256':inputs[str(native_path)],'reference_inputs_sha256':prepared_hash,'original_binary_sha256':binary_hash,
            'original_source_sha256':prepared['files'],'locked_packages':prepared['packages'],'registry_packages':5,
            'one_shared_cargo_build':True,'records':records,'domains':domains,'inputs':inputs,
            'cases':sum(DOMAIN_CASES.values()),'capture_predicate_cases':1,'removed_environment_keys':list(REMOVED_ENV),
            'runtime_rust_fallback':False,'unconstrained_regex_resources_closed':False}
    (output/'execution-progress.json').write_text(json.dumps({'status':'PASS','records':records},sort_keys=True,indent=2)+'\n')
    (output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items()if k not in ['records','domains','inputs']},sort_keys=True))


if __name__=='__main__':main()
