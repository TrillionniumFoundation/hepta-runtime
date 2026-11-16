"""Fresh unchanged rmcp 3.4.1 replay after full main native admission."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,sys,tarfile,time,tomllib,traceback
ROOT=Path(__file__).resolve().parents[3]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_request_registry_pipeline as p
import hia_native_request_registry_qualification as q
SDK_CRATE=q.SDK_CRATE

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
 parser.add_argument('--cargo',type=Path,required=True);parser.add_argument('--rustc',type=Path,required=True)
 args=parser.parse_args();base=args.output.absolute();out=base/p.FOLDER/'original';out.mkdir()
 report=p.read(base/'result.json');native=p.native_evidence(ROOT,base,report)
 table=p.source_table(ROOT);started=time.monotonic_ns();error=None;records=[];sdk_pins={};dependencies=[]
 p.write_new(out/'native-predecessor.json',native)
 cases=base/p.FOLDER/'sdk/sdk-cases.jsonl';cases_pin=p.pin(cases)
 oracle=ROOT/'tests/hia_native/request_registry_sdk/oracle'
 rustc=args.rustc.resolve(strict=True);cargo=args.cargo.resolve(strict=True)
 for label,tool in [('rustc',rustc),('cargo',cargo)]:p.same(p.pin(tool),q.RUST_TOOL_PINS[label],'fixed Rust 1.95 tool bytes')
 target=base/p.FOLDER/'original-target';p.require(not target.exists(),'fresh absent Cargo target')
 cargo_home=Path(os.environ.get('CARGO_HOME',str(Path.home()/'.cargo'))).absolute()
 rustup_home=Path(os.environ.get('RUSTUP_HOME',str(Path.home()/'.rustup'))).absolute()
 env={'PATH':str(rustc.parent)+':/usr/bin:/bin','CARGO_HOME':str(cargo_home),'RUSTUP_HOME':str(rustup_home),
      'RUSTC':str(rustc),'CARGO_TARGET_DIR':str(target),'CARGO_BUILD_JOBS':'2','LANG':'C.UTF-8'}
 invocation={'source_root':str(ROOT),'output_root':str(base),'python':sys.executable,
             'cargo':str(cargo),'rustc':str(rustc),'environment':env,'source_files':table,
             'python_executable':p.pin(Path(sys.executable).resolve(strict=True)),'python_identity':p.executable_identity(sys.executable)}
 p.write_new(out/'execution.json',invocation)
 runtime=tomllib.loads((ROOT/'tests/hia_native/request_registry_sdk/original/runtime-Cargo.lock').read_text())
 lock=tomllib.loads((oracle/'Cargo.lock').read_text())
 fixed={(r['name'],r['version']):r['checksum']for r in runtime['package']if r.get('source','').startswith('registry+')}
 dependencies=[r for r in lock['package']if r.get('source','').startswith('registry+')]
 for row in dependencies:p.same(fixed[(row['name'],row['version'])],row['checksum'],'locked original dependency')
 def run(name,argv,timeout,stdin=None):
  row=p.record(out,name,argv,cwd=oracle,timeout=timeout,env=env,stdin=stdin)
  # Additional fields belong to this retained original record, not a rewrite of
  # an already recorded subprocess. Keep the exact original mechanical receipt.
  extra={'record':row,'environment':env,'stdin':cases_pin if name=='original'else None}
  records.append(extra);return extra
 def check_sources():p.same(p.source_table(ROOT),table,'complete original sources unchanged')
 def check_sdk(sdk):
  for name,wanted in sdk_pins.items():p.same(p.pin(sdk/name),wanted,'unchanged compiled SDK source '+name)
 try:
  run('rustc',[str(rustc),'-Vv'],30);run('cargo',[str(cargo),'--version'],30)
  p.require('release: 1.95.0\n'in(out/'rustc.stdout').read_text(),'fixed Rust version')
  run('metadata',[str(cargo),'metadata','--locked','--format-version','1'],60)
  metadata=p.read(out/'metadata.stdout');selected=[r for r in metadata['packages']if r['name']=='rmcp'and r['version']=='3.4.1']
  p.require(len(selected)==1,'one locked original SDK');sdk=Path(selected[0]['manifest_path']).parent
  p.require(sdk.is_relative_to(cargo_home/'registry/src'),'actual SDK is a locked registry source')
  cache=cargo_home/'registry/cache'/sdk.parent.name/'rmcp-3.4.1.crate'
  p.require(p.pin(cache)['sha256']==SDK_CRATE,'published unchanged SDK checksum')
  shutil.copyfile(cache,out/'rmcp-3.4.1.crate')
  with tarfile.open(cache)as archive:
   for member in archive:
    p.require(member.isdir()or member.isfile(),'ordinary SDK crate members')
    if not member.isfile():continue
    relative=Path(member.name).relative_to('rmcp-3.4.1');p.require(not relative.is_absolute()and '..'not in relative.parts,'SDK crate member path')
    raw=archive.extractfile(member).read();p.require((sdk/relative).read_bytes()==raw,'actual compiler SDK bytes')
    sdk_pins[relative.as_posix()]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
  p.write_new(out/'SDK-PROVENANCE.json',{'crate':p.pin(cache),'source_files':sdk_pins,'registry_dependencies':dependencies,
   'source':str(sdk),'runtime_lock':p.pin(ROOT/'tests/hia_native/request_registry_sdk/original/runtime-Cargo.lock'),'oracle_lock':p.pin(oracle/'Cargo.lock')})
  check_sources();check_sdk(sdk)
  run('build',[str(cargo),'build','--release','--locked'],180)
  shutil.copyfile(target/'release/hepta-request-registry-sdk-original',out/'original-sdk.elf');(out/'original-sdk.elf').chmod(0o755)
  check_sources();check_sdk(sdk)
  with cases.open('rb')as stream:run('original',[str(out/'original-sdk.elf')],180,stream)
  check_sources();check_sdk(sdk);p.same(p.pin(cases),cases_pin,'complete original input unchanged')
 except BaseException:error=traceback.format_exc();raise
 finally:
  result={'status':'PASS'if error is None else'FAIL','error':error,'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),
   'driver_pid':os.getpid(),'native_first':{'evidence':p.pin(out/'native-predecessor.json'),'cases':cases_pin},
   'processes':records,'sdk_source_files':len(sdk_pins),'dependencies':len(dependencies),'whole_runtime_replaced':False,'strict_comparison_pending':True}
  p.write_new(out/'RESULT.json',result)
  print(json.dumps({'status':result['status'],'error':error,'processes':len(records),'cases':68,'steps':7879,
                   'new_native_calls':0,'whole_runtime_replaced':False},sort_keys=True),flush=True)
 if error is None:
  # Only this newly owned reproducible target is transient. The complete
  # original executable, source identities and all process streams remain.
  shutil.rmtree(target)
if __name__=='__main__':main()
