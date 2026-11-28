from pathlib import Path
import os,sys,json,hashlib,subprocess,tarfile,time,traceback,shutil
os.umask(0o022);base=Path('/Users/qianqi/work/hia-runtime-rea-formats-20261128-2ac5');source=base/'source';out=base/'asar-complete-component-integration-v1';out.mkdir(mode=0o700,exist_ok=False)
(out/'driver.py').write_text(sys.argv[1]);payload=json.loads(sys.argv[2]);start=time.monotonic();rows=[];sha=lambda b:hashlib.sha256(b).hexdigest()
def run(label,argv,timeout=120):
 tick=time.monotonic();p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=out,timeout=timeout)
 (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);rows.append({'label':label,'returncode':p.returncode,'seconds':time.monotonic()-tick});assert p.returncode==0,p.stderr
try:
 head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip();assert head=='3161db718a193b69631fea3e68655f82d02aa334'
 (out/'initial-status.txt').write_bytes(subprocess.check_output(['git','status','--short'],cwd=source))
 archive=out/'complete-asar-native-and-original-proof.tar.gz';remote='desktop:/home/qian-qi/hia-runtime-rea-formats-20261128-2ac5/asar-complete-component-capture-v1/'
 run('copy-archive',['/usr/bin/scp',remote+archive.name,str(archive)])
 assert archive.stat().st_size==60875060 and sha(archive.read_bytes())=='ff1ceddcc6ed09de401058ac62ff5a23952800ec5596b5d31c118df0148b47e3'
 run('copy-capture-terminal',['/usr/bin/scp',remote+'terminal.json',str(out/'capture-terminal.json')])
 run('copy-capture-driver',['/usr/bin/scp',remote+'driver.py',str(out/'capture-driver.py')])
 capture=json.loads((out/'capture-terminal.json').read_bytes());assert capture['status']=='COMPLETE_ORIGINAL_INPUTS_OUTPUTS_AND_FAILURES_CAPTURED'and capture['archive_sha256']==sha(archive.read_bytes())
 existing=['native/rea_asar_parser.hepta','native/rea_asar_parser_composition.json','scripts/author_rea_asar.py','scripts/rea_asar_author_tables.py','scripts/rea_asar_parser_source.py.txt','docs/rea_asar_parser_abi.md','native/rea_asar_private_lowering.hepta','native/rea_asar_private_lowering_composition.json','scripts/author_private_sha_x64.py','scripts/build_rea_asar_component.py','scripts/private_sha_x64_source.py.txt']
 desired={n:(source/n).read_bytes()for n in existing}
 included=['prepare_asar_oracle.py','qualify_rea_asar_abi.py','qualify_rea_asar_differential.py','qualify_rea_asar_limits.py','qualify_rea_asar_worker_limits.py','qualify_rea_asar_private_sha.py','qualify_rea_asar_lowered_sha.py','rea_asar_native_transport.py','rea_asar_oracle.Cargo.lock','asar_native_driver.rs']
 for n in included:desired['tests/hia_native/rea_asar/'+n]=payload[n].encode()
 required={'asar-final-component-gates-v2/terminal.json':'FINAL_ASAR_COMPONENT_GATES_PASS','asar-reproducible-component-build-v1/terminal.json':'REPRODUCIBLE_ASAR_COMPONENT_BUILD_PASS','asar-private-sha-x64-build-v3/terminal.json':'PASS','asar-worker-limits-v4/terminal.json':'PASS','asar-abi-v2/terminal.json':'PASS','asar-differential-v2/terminal.json':'PASS','asar-limits-v3/terminal.json':'PASS'}
 with tarfile.open(archive,'r|gz')as tar:
  first=next(iter(tar));assert first.name=='manifest.json'and first.isfile()
  manifest_raw=tar.extractfile(first).read();assert sha(manifest_raw)==capture['manifest_sha256']
  manifest=json.loads(manifest_raw);pins=manifest['files'];assert len(pins)==4661 and len(manifest['directories'])==206 and manifest['logical_bytes']==4226772695
  objects={}
  for n,pin in pins.items():
   if pin['sha256']in objects:assert objects[pin['sha256']]==pin['bytes']
   objects[pin['sha256']]=pin['bytes']
  assert len(objects)==2866
  matched={n:[m for m,pin in pins.items()if pin['sha256']==sha(raw)and pin['bytes']==len(raw)]for n,raw in desired.items()}
  missing={n:sha(desired[n])for n,m in matched.items()if not m}
  (out/'qualified-source-matches.json').write_text(json.dumps({'matched':matched,'missing':missing},sort_keys=True,indent=2)+'\n')
  if missing:print(json.dumps({'missing_source_matches':missing}),flush=True)
  wanted={pins[n]['sha256']:n for n in required};saved={};checked=set()
  for m in tar:
   if m.name=='manifest.json':continue
   assert m.isfile()and m.mode==0o600 and m.name.startswith('objects/')and len(m.name)==72
   h=m.name[8:];assert h in objects and h not in checked and m.size==objects[h]
   f=tar.extractfile(m);actual=hashlib.sha256();parts=[]
   while block:=f.read(1048576):
    actual.update(block)
    if h in wanted:parts.append(block)
   assert actual.hexdigest()==h,m.name;checked.add(h)
   if h in wanted:saved[wanted[h]]=b''.join(parts)
  assert checked==set(objects)
 assert len(saved)==len(required)
 for n,want in required.items():assert json.loads(saved[n])['status']==want
 if missing:raise ValueError('Current qualification source is not among the exact executed inputs')
 for n,raw in desired.items():
  p=source/n
  if p.exists():assert p.read_bytes()==raw
  else:p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
 # The same new QA file was first staged next to the driver while validating
 # construction. Keep its one canonical test location; it was never tracked.
 duplicate=source/'scripts/qualify_rea_asar_lowered_sha.py'
 assert duplicate.read_bytes()==desired['tests/hia_native/rea_asar/qualify_rea_asar_lowered_sha.py']
 assert subprocess.check_output(['git','ls-files','--',str(duplicate.relative_to(source))],cwd=source)==b''
 duplicate.unlink()
 proof=source/'qualification/rea-asar-native-20261128';proof.mkdir(parents=True,exist_ok=False)
 for p,n in [(archive,archive.name),(out/'capture-terminal.json','capture-terminal.json'),(out/'capture-driver.py','capture-driver.py'),(out/'driver.py','integration-driver.py')]:shutil.copy2(p,proof/n)
 (proof/'all-original-members.json').write_bytes(manifest_raw)
 readback={'status':'INDEPENDENT_ALL_OBJECTS_AND_COMPLETE_MANIFEST_VERIFIED','members':len(pins),'unique_objects':len(objects),'logical_bytes':manifest['logical_bytes'],'archive_bytes':archive.stat().st_size,'archive_sha256':sha(archive.read_bytes()),'manifest_sha256':sha(manifest_raw),'qualified_source_matches':matched,'source_head':head,'seconds':time.monotonic()-start,'public_route_qualified':False,'whole_runtime_replaced':False}
 (proof/'independent-readback.json').write_text(json.dumps(readback,sort_keys=True,indent=2)+'\n')
 for n,raw in saved.items():
  dst=proof/'final-receipts'/n;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw)
 report={'schema':'hepta.runtime.rea-asar-native-component-integration.v2','base':head,'source_files':{n:{'bytes':len(raw),'sha256':sha(raw)}for n,raw in desired.items()},'qualification':capture,'independent_readback':readback,'explicit_hia_native_lowering':True,'compiler_changed':False,'product_is_direct_b3_output':False,'old_production_removed':False,'public_route_qualified':False,'whole_runtime_replaced':False}
 (proof/'integration.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 report.update(status='COMPLETE_COMPONENT_SOURCES_AND_PROOFS_READY',source_paths=len(desired),proof_paths=sum(p.is_file()for p in proof.rglob('*')),rows=rows,seconds=time.monotonic()-start)
except BaseException as e:
 report={'status':'FAILED','error':repr(e),'traceback':traceback.format_exc(),'rows':rows,'public_route_qualified':False,'whole_runtime_replaced':False}
 (out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report),flush=True);raise
(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in ['source_files','qualification','independent_readback']},sort_keys=True),flush=True)
