from pathlib import Path
import ast,ctypes,fcntl,hashlib,importlib.util,json,os,shutil,stat,struct,subprocess,sys,time,traceback,types,unittest
R=Path('/home/qian-qi/hia-runtime-process-owner-20261128-2ac5')
I=R/'job-receipt-native-inputs-v1';Q=R/'job-receipt-native-functional-v2';Q.mkdir(mode=0o700)
S=Q/'source';PEER=Path('/home/qian-qi/hia-runtime-filebytes-20261128-2ac5');H=PEER/'pinned-hepta-d3e2'
shutil.copytree(R/'identity-native-v1/source',S,copy_function=shutil.copy2,ignore=shutil.ignore_patterns('__pycache__','.git'))
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
manifest=json.loads((I/'manifest.json').read_bytes())
for row in manifest:
 raw=(I/row['name']).read_bytes();assert len(raw)==row['bytes'] and SHA(raw)==row['sha256']
 dst=S/row['path'];dst.parent.mkdir(parents=True,exist_ok=True)
 assert not dst.exists(),str(dst);dst.write_bytes(raw);dst.chmod(row['mode'])
frozen={}
def read(p):
 p=Path(p);a=p.lstat();assert stat.S_ISREG(a.st_mode) and a.st_nlink==1,str(p)
 raw=p.read_bytes();b=p.lstat()
 stamp=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 assert stamp(a)==stamp(b),str(p)
 row={'bytes':len(raw),'sha256':SHA(raw),'mode':stat.S_IMODE(a.st_mode)}
 if str(p) in frozen:assert frozen[str(p)]==row,str(p)
 frozen[str(p)]=row;return raw
for p in S.rglob('*'):
 if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts:read(p)
read(Path(__file__))
os.environ.update(LC_ALL='C',LANG='C',TMPDIR=str(Q/'tmp'));(Q/'tmp').mkdir(mode=0o700)
sys.path.insert(0,str(S/'scripts'))
from hia_native_loader import NativeModule
start=time.monotonic();failure=None;report={}
try:
 policy_m=R/'job-receipt-native-functional-v1/build/modules/process-job-receipt/manifest.json'
 packer_m=R/'job-receipt-native-functional-v1/build/modules/process-job-receipt-packer/manifest.json'
 policy_meta=json.loads(read(policy_m));code=read(policy_m.parent/policy_meta['image'])
 packer_meta=json.loads(read(packer_m));read(packer_m.parent/packer_meta['image'])
 assert read(policy_m.parent/policy_meta['source'])==read(S/'native/process_job_receipt.hepta')
 assert read(packer_m.parent/packer_meta['source'])==read(S/'native/process_job_receipt_packer.hepta')
 # Explicit QA preparation: execute the four complete captured original checker
 # function bodies; the older compiler distribution does not ship these helpers.
 sys.path.insert(0,str(H))
 from hepta import hia_agent_assembly as assembly
 read(Path(assembly.__file__))
 original_raw=read(S/'authoring/process_owner_v1/job_receipt_original/generate_hia_native_filter.py')
 assert SHA(original_raw)=='27f3987cf94d33fca43dbfd23948d78cf9f9448dc565bf487e30891672dbcb80'
 original=ast.parse(original_raw)
 names=('_binding_declaration','read_adapter_binding','verify_adapter','elf_header')
 nodes=[next(n for n in original.body if isinstance(n,ast.FunctionDef) and n.name==name) for name in names]
 checker={'assemble_program':assembly.assemble_program,'sha256':hashlib.sha256,'struct':struct}
 checked_ast=ast.Module(body=nodes,type_ignores=[]);ast.fix_missing_locations(checked_ast)
 exec(compile(checked_ast,str(S/'authoring/process_owner_v1/job_receipt_original/generate_hia_native_filter.py'),'exec'),checker)
 filter_api=types.SimpleNamespace(**{name:checker[name] for name in names})
 (Q/'checker-preparation.json').write_text(json.dumps({'scope':'EXACT_ORIGINAL_FUNCTION_BODIES','whole_source_sha256':SHA(original_raw),'functions':names,'function_ast_sha256':SHA(ast.dump(checked_ast,include_attributes=False).encode()),'reused_actual_compilation':str(policy_m.parent.parent.parent)},indent=2)+'\n')
 packer=NativeModule(packer_m,manifest_sha256=SHA(read(packer_m)))
 packet=struct.pack('<8sQ',b'HIAJPK01',len(code))+code
 result,out,work=packer.invoke_raw(packet,output_capacity=1<<20,workspace_capacity=65536)
 assert 0<result<=len(out) and out[result:]==bytes(len(out)-result)
 elf=out[:result]
 binding=filter_api.read_adapter_binding(read(S/'native/process_job_receipt_packer.hepta'),read(S/'authoring/process_owner_v1/job_receipt_original/hia_job_receipt_syscalls.S'),calls=1)
 filter_api.verify_adapter(elf,code,binding,entries=(0,))
 exe=Q/'hia-process-job-receipt';exe.write_bytes(elf);exe.chmod(0o500)
 (Q/'pack-request.bin').write_bytes(packet);(Q/'pack-output.bin').write_bytes(out);(Q/'pack-workspace.bin').write_bytes(work)
 pack_refusals=[]
 for label,wire in (('empty',b''),('truncated',packet[:-1]),('trailing',packet+b'\0'),('magic',b'X'+packet[1:]),('empty-part',packet[:8]+bytes(8)+packet[16:])):
  rc,buf,state=packer.invoke_raw(wire,output_capacity=1<<20,workspace_capacity=65536,output_fill=165)
  assert rc==0xffffffff and buf==b'\xa5'*(1<<20),(label,rc)
  pack_refusals.append({'case':label,'code':rc})
 packer.close()
 os.environ['HIA_TEST_JOB_RECEIPT_EXE']=str(exe)
 original_test=S/'authoring/process_owner_v1/job_receipt_original/test_hia_job_receipt.py'
 spec=importlib.util.spec_from_file_location('exact_original_job_receipt_functions',original_test)
 tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
 selected=(
  'test_both_durable_publications_preserve_bytes_and_mode',
  'test_existing_temporary_is_not_overwritten_or_promoted',
  'test_rename_failure_is_not_success_or_replayed',
  'test_original_registry_size_boundary',
  'test_terminal_wire_publishes_the_existing_newline_terminated_files',
  'test_owner_wire_creates_both_exact_records_and_never_replaces_previous_intent',
  'test_owner_wire_stops_at_partial_publication_without_retry',
  'test_native_capture_preserves_isolated_extent_and_actual_io',
  'test_original_wait_holds_custody_and_returns_real_wait_status')
 suite=unittest.TestSuite(tests.JobReceiptExecutableTests(name) for name in selected)
 with (Q/'original-functional-methods.log').open('w') as log:
  result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
 assert result.testsRun==len(selected) and result.wasSuccessful() and not result.skipped
 # A real parsed record is durably replaced through the original HIA writer.
 record_m=R/'record-native-compile-v3/build/modules/process-record/manifest.json'
 raw=read(record_m);record_meta=json.loads(raw)
 for name in ('source','image'):read(record_m.parent/record_meta[name])
 record=NativeModule(record_m,manifest_sha256=SHA(raw))
 root=Q/'ordinary-job-registry';root.mkdir(mode=0o700)
 common={'execution_mode':'operator','system_jobctl':False,'id':'component-job-1',
  'host':'configured-test-host','ssh_target':'configured-target','unit':'hepta-job-component',
  'remote_job_dir':'/home/test/state/jobs/component-job-1','executable':'/usr/bin/true',
  'args':['ordinary','quote"','utf8-中文'],'cwd':None,'env_keys':['LANG'],
  'created_unix_ms':340282366920938463463374607431768211455,'idempotency_key':'owned-component-key',
  'request_fingerprint':18446744073709551615,'request_digest':'0'*64,
  'launch_state':'pending','launch_error':None}
 transitions=[]
 for ordinal,state in enumerate(('pending','launched','launch_unknown'),1):
  value={**common,'launch_state':state,'launch_error':None if state!='launch_unknown' else 'Remote launch outcome unavailable'}
  source=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
  frame=b'HPRJRQ01'+struct.pack('<4Q',3,111,0,len(source))+source
  pretty=record.invoke(frame,output_capacity=1<<20,workspace_capacity=4<<20)
  assert json.loads(pretty)==value and pretty.endswith(b'}')
  name=value['id'].encode();wire=struct.pack('<8s3Q',b'HIAJRQ01',len(pretty),os.getpid(),len(name))+name+pretty
  sourcefd=os.memfd_create('ordinary-job-record',os.MFD_ALLOW_SEALING);directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
  try:
   assert os.write(sourcefd,wire)==len(wire)
   fcntl.fcntl(sourcefd,fcntl.F_ADD_SEALS,15)
   done=subprocess.run([str(exe)],stdin=sourcefd,stdout=directory,stderr=subprocess.PIPE,env={'PATH':''},timeout=5)
  finally:os.close(sourcefd);os.close(directory)
  assert done.returncode==0 and done.stderr==struct.pack('<8sQq',b'HIAJRW01',6,0),(state,done.returncode,done.stderr)
  path=root/(value['id']+'.json');st=path.lstat()
  assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and path.read_bytes()==pretty
  (Q/('transition-'+str(ordinal)+'.request')).write_bytes(wire)
  (Q/('transition-'+str(ordinal)+'.record')).write_bytes(pretty)
  (Q/('transition-'+str(ordinal)+'.ack')).write_bytes(done.stderr)
  transitions.append({'state':state,'bytes':len(pretty),'sha256':SHA(pretty),'inode':st.st_ino,'mode':stat.S_IMODE(st.st_mode),'ack_phase':6,'ack_code':0})
 assert len({x['inode'] for x in transitions})>=2
 record.close()
 report={'scope':'ORDINARY_ORIGINAL_HIA_JOB_RECEIPT_COMPONENT','original_methods':list(selected),
  'methods_run':result.testsRun,'skipped':0,'pack_refusals':pack_refusals,'actual_record_transitions':transitions,
  'publisher_source_sha256':policy_meta['source_sha256'],'packer_source_sha256':packer_meta['source_sha256'],
  'compiler_sha256':policy_meta['compiler_sha256'],'image_bytes':len(elf),'image_sha256':SHA(elf),
  'original_six_stage_protocol':True,'lost_ack_retry_added':False,'reader_or_public_process_qualified':False}
except BaseException:
 failure=traceback.format_exc();(Q/'failure.txt').write_text(failure);traceback.print_exc()
finally:
 for p in tuple(frozen):read(p)
 (Q/'physical-inputs.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n')
 report.update({'passed':failure is None,'source_terminal_stable':True,'elapsed_seconds':time.monotonic()-start,'failure':failure})
 (Q/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report),flush=True)
if failure:raise SystemExit(1)
