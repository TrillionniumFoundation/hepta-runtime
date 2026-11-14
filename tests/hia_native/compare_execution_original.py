"""Fresh locked Rust compilation and complete original shadow/JSON replay."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,shutil,subprocess,sys,time,traceback
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'tests/hia_native'))
from hia_native_execution_qualification import source_pins,STREAMS,stream_identity,read,sha,require,exact,import_driver

def identity(path):
    with Path(path).open('rb') as stream:
        value=hashlib.sha256();size=0
        while raw:=stream.read(1<<20):size+=len(raw);value.update(raw)
    return {'bytes':size,'sha256':value.hexdigest()}

def run(runtime,corpus,output,*,rustc,cargo,offline=False):
    runtime=runtime.resolve(strict=True);corpus=corpus.resolve(strict=True);output=output.resolve()
    output.mkdir(parents=True,exist_ok=False,mode=0o700);started=time.monotonic()
    report={'schema':'hepta.runtime.execution-original-comparison.v1','status':'FAIL',
            'production_activated':False,'whole_runtime_replaced':False,'old_stack_removal_qualified':False}
    checks=[]
    def command(name,args,*,stdin=None):
        before=time.monotonic();remaining=180-(before-started)
        require(remaining>0,'original recipe exhausted its unchanged 180-second deadline')
        stdout=output/(name+'.stdout');stderr=output/(name+'.stderr')
        with stdout.open('xb') as out,stderr.open('xb') as err:
            completed=subprocess.run([str(x) for x in args],stdin=stdin,stdout=out,stderr=err,
                                     cwd=output,env=env,timeout=remaining)
        row={'name':name,'command':[str(x) for x in args],'exit_code':completed.returncode,
             'elapsed_seconds':time.monotonic()-before,'stdout':identity(stdout),'stderr':identity(stderr)}
        checks.append(row);require(completed.returncode==0,'actual original process failed: '+name)
        return stdout
    try:
        pins=source_pins(runtime);report['source_pins']=pins
        for name in ('core/requests.hex.gz','core/native-output.hex.gz','json/requests.hex.gz','json/native-output.hex.gz'):
            require(stream_identity(corpus/name)==STREAMS[name],'native replay stream changed: '+name)
        project=output/'project';recipe=import_driver(runtime).prepare(runtime,project)
        report['source_recipe']=recipe
        env=dict(os.environ)
        for key in list(env):
            if key.startswith(('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_TARGET_')):env.pop(key)
        env.update(RUSTC=str(rustc),RUSTUP_TOOLCHAIN='1.95.0',CARGO_TARGET_DIR=str(output/'target'),CARGO_BUILD_JOBS='2')
        tmp=output/'tmp';tmp.mkdir();env['TMPDIR']=str(tmp)
        version=command('rust-version',[rustc,'--version','--verbose'])
        require(read(version).startswith(b'rustc 1.95.0 '),'unexpected selected original compiler')
        flag=['--offline'] if offline else []
        command('locked-build',[cargo,'build','--release','--locked','--manifest-path',project/'Cargo.toml','--bins',*flag])
        tests=command('original-tests',[cargo,'test','--release','--locked','--manifest-path',project/'Cargo.toml','--bin','execution-core-original',*flag])
        require(b'test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' in read(tests),'original tests were incomplete')
        require(sha(read(project/'Cargo.lock'))==recipe['lock_sha256'],'Cargo mutated the frozen lock')
        before_inputs={name:identity(corpus/name) for name in ('core/requests.hex.gz','core/native-output.hex.gz','json/requests.hex.gz','json/native-output.hex.gz')}
        outputs={}
        for kind,name in [('core','execution-core-original'),('json','execution-json-original')]:
            input_path=output/(kind+'.input.hex')
            with gzip.open(corpus/kind/'requests.hex.gz','rb') as compressed,input_path.open('xb') as target:
                shutil.copyfileobj(compressed,target,1<<20)
            expected_input=STREAMS[kind+'/requests.hex.gz']
            exact(identity(input_path),{'bytes':expected_input[0],'sha256':expected_input[1]},'actual original input is incomplete')
            binary=output/'target/release'/name;require(binary.is_file() and not binary.is_symlink(),'original binary missing')
            report.setdefault('binaries',{})[kind]=identity(binary)
            with input_path.open('rb') as data:actual=command(kind+'-replay',[binary],stdin=data)
            outputs[kind]=actual
        core_expected=STREAMS['core/native-output.hex.gz']
        exact(identity(outputs['core']),{'bytes':core_expected[0],'sha256':core_expected[1]},'complete actual original core output differs')
        normalized=output/'json-normalized.hex';accepted=rows=0
        with outputs['json'].open('rb') as actual,normalized.open('xb') as stream:
            for line in actual:
                row=json.loads(line);require(type(row.get('accepted')) is bool,'original JSON result shape changed')
                if row['accepted']:
                    value=row['value'];data=bytes.fromhex(value['packet']) if 'packet' in value else value['canonical'].encode()
                    encoded=f'{len(data):08x}:'.encode()+data.hex().encode()+b'\n';accepted+=1
                else:encoded=b'ffffffff:\n'
                stream.write(encoded);rows+=1
        require(rows==14960 and accepted==7234,'original JSON case coverage differs')
        expected=STREAMS['json/native-output.hex.gz']
        exact(identity(normalized),{'bytes':expected[0],'sha256':expected[1]},'complete actual original JSON output differs')
        raw_json=identity(outputs['json'])
        require(raw_json=={'bytes':58230252,'sha256':'534afa03ae3a6232a19e8f66f1cbd70d372ac421d79430421b1485e64e897321'},'actual original typed errors/results differ')
        with gzip.open(runtime/'tests/hia_native/execution_json_original_rows.jsonl.gz','rb') as expected_stream,outputs['json'].open('rb') as actual_stream:
            while raw:=expected_stream.read(1<<20):require(actual_stream.read(len(raw))==raw,'retained actual original expectation differs')
            require(actual_stream.read(1)==b'','unexpected original trailing output')
        for kind,path in outputs.items():
            with path.open('rb') as source,gzip.open(output/(kind+'-original.stdout.gz'),'wb') as target:shutil.copyfileobj(source,target,1<<20)
        require(source_pins(runtime)==pins,'sources changed during original comparison')
        exact({name:identity(corpus/name) for name in before_inputs},before_inputs,'native input changed during replay')
        for name,expected_sha in recipe['files'].items():require(sha(read(project/name))==expected_sha,'original project source changed')
        report.update(status='PASS',checks=checks,core_cases=73349,json_cases=14960,json_accepted=7234,
                      original_test_cases=5,original_core_output=identity(outputs['core']),
                      original_json_output=raw_json,normalized_json_output=identity(normalized),
                      native_inputs=before_inputs,elapsed_seconds=time.monotonic()-started)
    except BaseException as error:
        report.update(error=str(error),traceback=traceback.format_exc(),checks=checks,elapsed_seconds=time.monotonic()-started)
        (output/'comparison.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps(report,sort_keys=True));raise
    report['artifacts']={path.relative_to(output).as_posix():identity(path) for path in output.rglob('*')
                         if path.is_file() and not path.is_relative_to(output/'target')}
    (output/'comparison.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True));return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,default=ROOT);p.add_argument('--corpus',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--rustc',type=Path,required=True);p.add_argument('--cargo',type=Path,required=True)
    p.add_argument('--offline',action='store_true');a=p.parse_args()
    run(a.runtime,a.corpus,a.output,rustc=a.rustc,cargo=a.cargo,offline=a.offline)
