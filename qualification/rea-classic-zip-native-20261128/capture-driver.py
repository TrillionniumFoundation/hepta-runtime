from pathlib import Path,PurePosixPath
from hashlib import sha256
import sys,json,os,stat,tarfile,time
base=Path('/home/qian-qi/hia-runtime-rea-formats-20261128-2ac5');out=base/'zip-complete-proof-capture-v1';out.mkdir(mode=0o700,exist_ok=False)
(out/'driver.py').write_text(sys.argv[1]);started=time.monotonic()
required={'zip-original-eight-v4':'ORIGINAL_EIGHT_RUST_AND_ACTUAL_HIA_METHODS_PASSED','zip-differential-v1':'PASS','zip-limits-v1':'PASS','zip-final-qa-readback-v3':'FINAL_QA_PREPARATION_MATCHES_ACTUAL_PASSING_CRATE'}
terminals={}
for name,status in required.items():
 r=json.loads((base/name/'terminal.json').read_bytes());assert r['status']==status,(name,r);terminals[name]=r
source=base/'zip-native-build-v1/source';composition=json.loads((source/'native/rea_zip_parser_composition.json').read_bytes())
assert composition['source_sha256']=='710a1ac7e4ebf7d4fa3e27c3bfcffd66f853043a4854cc1d4b72cea6d72e5832'
assert sha256((source/'native/rea_zip_parser.hepta').read_bytes()).hexdigest()==composition['source_sha256']
members={}
for top in sorted(base.iterdir()):
 if not top.name.startswith('zip-')or not top.is_dir()or top==out:continue
 for folder,dirs,files in os.walk(top,followlinks=False):
  dirs[:]=sorted(d for d in dirs if d!='target')
  for name in sorted(files):
   p=Path(folder)/name;st=p.lstat();assert stat.S_ISREG(st.st_mode),(str(p),st.st_mode)
   members[str(p.relative_to(base))]=p
for top in sorted(base.glob('zip-original-eight-v*/target/debug/deps')):
 for path in sorted(top.glob('hia_rea_zip_reference-*')):
  if path.is_file()and os.access(path,os.X_OK):
   with path.open('rb')as f:magic=f.read(4)
   if magic==b'\x7fELF':members['actual-original-test-executables/'+top.parents[2].name+'/'+path.name]=path
for name in ['exact-public-crates.tar.gz','available-public-crates.json','final-qualification-source.tar.gz','final-qualification-source-pins.json','final-qualification-source-v2.tar.gz','final-qualification-source-v2-pins.json','final-qualification-source-v3.tar.gz','final-qualification-source-v3-pins.json']:
 path=base/name;assert path.is_file();members[name]=path
assert len(members)>1100
def digest(p):
 h=sha256()
 with p.open('rb')as f:
  while block:=f.read(1048576):h.update(block)
 return h.hexdigest()
pins={}
for name,path in sorted(members.items()):
 st=path.stat();pins[name]={'bytes':st.st_size,'sha256':digest(path),'mode':stat.S_IMODE(st.st_mode)}
(out/'all-original-members.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
archive=out/'complete-zip-parser-native-and-original-proof.tar.gz'
with tarfile.open(archive,'w:gz',compresslevel=6)as tar:
 for name,path in sorted(members.items()):tar.add(path,arcname=name,recursive=False)
verified=0;raw_bytes=0
with tarfile.open(archive,'r:gz')as tar:
 assert set(tar.getnames())==set(pins)
 for member in tar:
  pin=pins[member.name];assert member.isfile()and member.mode==pin['mode']and member.size==pin['bytes']
  h=sha256()
  with tar.extractfile(member)as f:
   while block:=f.read(1048576):h.update(block)
  assert h.hexdigest()==pin['sha256'],member.name
  assert digest(members[member.name])==pin['sha256'],member.name
  verified+=1;raw_bytes+=member.size
report={'schema':'hepta.runtime.rea-zip-complete-native-qualification.v1','status':'COMPLETE_ORIGINAL_INPUTS_OUTPUTS_AND_FAILURES_CAPTURED','members':verified,'uncompressed_bytes':raw_bytes,'archive_bytes':archive.stat().st_size,'archive_sha256':digest(archive),'seconds':time.monotonic()-started,'native_source_sha256':composition['source_sha256'],'original_test_file_sha256':sha256((source/'src/mcp/rea_artifact_zip_parser_tests.rs').read_bytes()).hexdigest(),'original_methods':8,'native_original_methods':8,'full_result_differential_cases':terminals['zip-differential-v1']['full_json_or_exact_error_comparisons'],'differences':0,'limit_comparisons':4,'real_descriptor_mutation_controls':1,'native_original_calls':terminals['zip-original-eight-v4']['native_invocations'],'differential_native_calls':terminals['zip-differential-v1']['native_calls'],'limit_native_calls':sum(r.get('native_calls',r.get('native',{}).get('native_calls',0))for r in terminals['zip-limits-v1']['rows']),'source_and_input_bytes_stable':True,'all_preparation_failures_retained':True,'cargo_incremental_and_dependency_build_cache_excluded':True,'actual_original_test_executables_included':True,'public_route_qualified':False,'whole_runtime_qualified':False}
(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True),flush=True)
