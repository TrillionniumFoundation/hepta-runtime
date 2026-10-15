from pathlib import Path
import argparse,ast,contextlib,hashlib,importlib.abc,importlib.util,io,json,os,py_compile,re,stat,sys,tempfile,types
source=Path('/home/qian-qi/hepta-runtime-v9-ledger-rollback-drafts-20261013/tests/dc_functional_v9_rollback_ledger_host_acceptance.py')
pin='5d5edc3ac11db57e620fa6db71233e6f2b2360292b9705ccad464967da1a7cd6'
assert hashlib.sha256(source.read_bytes()).hexdigest()==pin
tree=ast.parse(source.read_text())
wanted={'bootstrap_pinned_dependencies','PinnedHelperSourceLoader','PinnedHelperSourceFinder','harness_inputs','sha256'}
nodes=[]
for n in tree.body:
 if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in wanted:nodes.append(n)
 if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BOOTSTRAP_DEPENDENCIES' for t in n.targets):nodes.append(n)
isolated=ast.Module(body=nodes,type_ignores=[])
log=[]
def record(name):log.append(name);print('PASS',name)
with tempfile.TemporaryDirectory(prefix='hepta-v9-ledger-r5-mock-only-') as tmp:
 root=Path(tmp);harness=root/'tests/mock-harness.py';harness.parent.mkdir();harness.write_text('mock-only-harness\n')
 ns={k:v for k,v in globals().items() if k in ('argparse','hashlib','importlib','json','os','re','stat','sys')}
 ns.update({'pathlib':__import__('pathlib'),'ROOT':root,'__file__':str(harness),'PINNED_HELPER_IMPORTS':{}})
 exec(compile(isolated,str(source)+'::<bootstrap AST only>','exec'),ns)
 dependencies={}
 for name in ns['BOOTSTRAP_DEPENDENCIES']:
  path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
  path.write_text("VALUE='good'\n" if name.endswith('.py') else "{}\n")
  dependencies[name]=hashlib.sha256(path.read_bytes()).hexdigest()
 contract=root/'v9-contract.json';contract.write_text('{}\n')
 manifest=root/'dependency-pins.json'
 def setup(deps=None,schema='hepta-v9-ledger-rollback-dependencies-v1',manifest_extra=None):
  value={'schema':schema,'dependencies':dependencies if deps is None else deps}
  if manifest_extra:value.update(manifest_extra)
  manifest.write_text(json.dumps(value))
  sys.argv=['mock-harness','--expected-dependency-pins-json',str(manifest),
   '--expected-dependency-manifest-sha256',hashlib.sha256(manifest.read_bytes()).hexdigest(),
   '--expected-harness-sha256',hashlib.sha256(harness.read_bytes()).hexdigest(),
   '--candidate-contract',str(contract),'--expected-contract-sha256',hashlib.sha256(contract.read_bytes()).hexdigest()]
 def rejected(label):
  try:ns['bootstrap_pinned_dependencies']()
  except RuntimeError:record(label);return
  raise AssertionError('invalid bootstrap accepted: '+label)
 setup();path,manifest_hash,verified=ns['bootstrap_pinned_dependencies']()
 assert verified==dependencies and path==manifest
 record('complete10dependency source pins plus harness manifest and contract accepted')
 setup();sys.argv[sys.argv.index('--expected-harness-sha256')+1]='0'*64;rejected('wrong harness source rejected before helper import')
 setup();sys.argv[sys.argv.index('--expected-dependency-manifest-sha256')+1]='0'*64;rejected('wrong manifest hash rejected before helper import')
 setup();sys.argv[sys.argv.index('--expected-contract-sha256')+1]='0'*64;rejected('wrong candidate contract rejected before helper import')
 setup({name:sha for i,(name,sha) in enumerate(dependencies.items()) if i});rejected('missing dependency rejected')
 setup({**dependencies,'tests/unreviewed.py':'0'*64});rejected('extra dependency rejected')
 setup(schema='wrong');rejected('wrong manifest schema rejected')
 setup(manifest_extra={'unknown':True});rejected('extra manifest root field rejected')
 setup();first=next(iter(dependencies));copy=dict(dependencies);copy[first]='0'*64;setup(copy);rejected('wrong source dependency rejected before any helper source executes')
 setup({**dependencies,'deploy/contracts/hepta-runtime-full-operator-v8.json':'0'*64});rejected('wrong frozen V8 contract rejected before helper import')
 setup();mp,mh,dp=ns['bootstrap_pinned_dependencies']()
 ns.update({'EXPLICIT_DEPENDENCY_PINS':dp,'DEPENDENCY_MANIFEST_PATH':mp,'DEPENDENCY_MANIFEST_SHA256':mh})
 before=ns['harness_inputs']()
 assert before['deploy/contracts/hepta-runtime-full-operator-v8.json']['sha256']==dependencies['deploy/contracts/hepta-runtime-full-operator-v8.json']
 frozen=root/'deploy/contracts/hepta-runtime-full-operator-v8.json';saved=frozen.read_bytes();frozen.write_bytes(b'tampered-after-loader\n')
 try:ns['harness_inputs']()
 except RuntimeError:record('frozen V8 mutation after loader caught by before/after input seal')
 else:raise AssertionError('V8 seal gap survived')
 frozen.write_bytes(saved)
 assert ns['harness_inputs']()==before
 record('restored frozen V8 exact bytes restore matching dependency seal')
 relative='deploy/mcp_tool_contract.py';artifact=root/relative
 artifact.write_text("raise AssertionError('unverified helper must never execute')\n")
 module=types.ModuleType('mock_contract')
 try:ns['PinnedHelperSourceLoader']('mcp_tool_contract',relative).exec_module(module)
 except RuntimeError:record('helper changed between bootstrap and import rejected before execution')
 else:raise AssertionError('changed source executed')
 artifact.write_text("VALUE='good'\n")
 poison=root/'poison.py';poison.write_text("VALUE='evil'\n")
 stamp=1700000000;os.utime(artifact,(stamp,stamp));os.utime(poison,(stamp,stamp))
 cached=Path(importlib.util.cache_from_source(str(artifact)));cached.parent.mkdir(exist_ok=True)
 py_compile.compile(str(poison),cfile=str(cached),dfile=str(artifact),doraise=True)
 assert len(artifact.read_bytes())==len(poison.read_bytes())
 module=types.ModuleType('mock_contract')
 ns['PinnedHelperSourceLoader']('mcp_tool_contract',relative).exec_module(module)
 assert module.VALUE=='good' and ns['PINNED_HELPER_IMPORTS'][relative]['compiled_from_verified_source_bytes']
 record('poisoned valid timestamp pycache bypassed; exact source bytes executed')
 finder=ns['PinnedHelperSourceFinder']()
 spec=finder.find_spec('mcp_tool_contract')
 assert Path(spec.origin)==artifact and isinstance(spec.loader,ns['PinnedHelperSourceLoader'])
 assert finder.find_spec('unreviewed_helper') is None
 record('finder binds reviewed helper names only to reviewed source paths')
assert 'HARNESS_ACCEPTANCE_ENABLED = False' in source.read_text()
for flag in ('--expected-dependency-pins-json','--expected-dependency-manifest-sha256','--expected-harness-sha256'):
 assert source.read_text().count(flag)>=3
record('cohort passes all3 explicit CLI pins to each member; draft stays disabled')
summary={'schema':'hepta-v9-ledger-bootstrap-mock-only-review-v1','source_sha256':pin,
 'mock_checks_passed':len(log),'checks':log,'actual_native_or_ssh_launched':False,
 'actual_acceptance_qualified':False,'full_dc_replacement_qualified':False}
out=Path('/home/qian-qi/hepta-runtime-v9-ledger-rollback-drafts-20261013/review')
(out/'r5-bootstrap-mock-only-receipt.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary))
