#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent V9 24-case offline health/multiread safety audit; no native qualification.

All HTTP, health, SSH, native and controller effects are mocked or inspected
only by AST. Generated population code is never executed. The frozen acceptance
harness and old health/multiread algorithms are pinned. This suite proves no
real-host qualification, signal qualification or full Desktop Commander cutover.
These are new explicitly pinned V9 adapters with the preserved mock/AST cases.
Historical V8 execution or loader approval is never borrowed.
"""
import ast,copy,hashlib,inspect,json,math,os,pathlib,sys,unittest
from unittest import mock
sys.dont_write_bytecode=True
root=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'tests'))
import argparse
import importlib.util
import re
import subprocess

BASELINE_HEAD="3c924c02416ef23f747d99a536c027fb246f2b8e"
BASELINE_JSON_SHA="4ef7eb288773b1e7f073ac07573669b2097c95187ebcf7eecb0ad38c10b98811"
ORIGINAL_V8_LOADER_SHA="ae4958001986b56e26871d7f1c2f3e7f543e6bda37fbc3d1b832c8435e84870e"
V8_CONTRACT_SHA="b64769210b9913fbdab28f7d0e95b7ef300d8710b3f1eeea74afcfac25b08318"
V9_CONTRACT_SHA="3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"

def _pinned_file(relative,expected):
    path=root/relative
    if not re.fullmatch('[0-9a-f]{64}',expected) or path.is_symlink() or not path.is_file():
        raise ValueError('ordinary explicitly pinned V9 safety input required')
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=expected:
        raise ValueError('V9 safety pre-import SHA differs: '+relative)
    return path

def _bootstrap():
    parser=argparse.ArgumentParser(description='V9-only mock/AST safety suite; explicit pre-import source pins')
    for name in ('signal-harness','health-harness','version-helper','loader','tool-helper','http-helper'):
        parser.add_argument('--expected-'+name+'-sha256',required=True)
    args,remaining=parser.parse_known_args()
    sys.argv=[sys.argv[0],*remaining]
    supplied={
        'tests/dc_functional_v9_signal_audit_acceptance.py':args.expected_signal_harness_sha256,
        'tests/dc_functional_v9_health_multiread_acceptance.py':args.expected_health_harness_sha256,
        'tests/dc_functional_v9_version_pin.py':args.expected_version_helper_sha256,
        'tests/dc_successor_contract.py':args.expected_loader_sha256,
        'deploy/mcp_tool_contract.py':args.expected_tool_helper_sha256,
        'tests/runtime_http_acceptance.py':args.expected_http_helper_sha256,
        'tests/dc_parity_release_six_host_acceptance.py':'f9ec9fdeb9a5aaa77cb6f813aa7afe4dd3db24f199731a20d579f687c3883227',
        'tests/dc_functional_v8_signal_audit_acceptance.py':'3b7c30bc34ed76fb2f194a26615004db5c22519182a29c9673b860aea858151e',
        'tests/dc_functional_v8_health_multiread_acceptance.py':'0812beefd088d523b89513b793da9c729fc64e1dc204406194e98ee72e0c23c8',
        'tests/dc_functional_v6_signal_audit_acceptance.py':'09c1a651992347eb02d70fb077db84713a807978b13482a3a96d96b44669aaf3',
        'tests/host_health_acceptance.py':'73f1105414b5362ab007843b4138ac7dc3bb43766630da7f70406283705cd5ea',
        'tests/multi_read_six_host_acceptance.py':'55b91cc2ef6207e0f23eefd3584a890621e8bf075926aa676f3b79debaf35f57',
        'deploy/contracts/hepta-runtime-full-operator-v8.json':V8_CONTRACT_SHA,
        'deploy/contracts/hepta-runtime-full-operator-v9.json':V9_CONTRACT_SHA,
        'tests/fixtures/dc_successor_contract_v8_ae495800.py':ORIGINAL_V8_LOADER_SHA,
        'docs/qualification/v9-harness-drafts-20261013/original-active-script-baseline-r1.json':BASELINE_JSON_SHA,
    }
    for relative,pin in supplied.items():_pinned_file(relative,pin)
    baseline=json.loads((root/'docs/qualification/v9-harness-drafts-20261013/original-active-script-baseline-r1.json').read_text())
    if (baseline['base_HEAD']!=BASELINE_HEAD or baseline['copied_script_and_contract_files']['tests/dc_successor_contract.py']['sha256']!=ORIGINAL_V8_LOADER_SHA):
        raise ValueError('original V8 loader baseline differs')
    historical=(root/'tests/fixtures/dc_successor_contract_v8_ae495800.py').read_bytes()
    if hashlib.sha256(historical).hexdigest()!=ORIGINAL_V8_LOADER_SHA:
        raise ValueError('archived historical loader bytes differ; old results cannot authorize the V9 loader')
    # Neither historical loader nor historical test main is imported/executed.
    return args,supplied,{'base_HEAD':BASELINE_HEAD,'loader_sha256':ORIGINAL_V8_LOADER_SHA,
        'loader_bytes':len(historical),'archived_byte_reference':'tests/fixtures/dc_successor_contract_v8_ae495800.py',
        'archived_loader_imported':False,'Git_history_object_needed':False,'historical_run_qualification_borrowed':False}

pin_args,PREIMPORT_PINS,ORIGINAL_V8_LOADER_PROVENANCE=_bootstrap()

def _load(relative,name):
    path=_pinned_file(relative,PREIMPORT_PINS[relative])
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

H=_load('tests/dc_functional_v9_health_multiread_acceptance.py','offline_v9_health')
F=_load('tests/dc_functional_v9_signal_audit_acceptance.py','offline_v9_signal')
paths=[root/'tests/dc_functional_v9_health_multiread_acceptance.py',root/'tests/host_health_acceptance.py',root/'tests/multi_read_six_host_acceptance.py',root/'tests/dc_functional_v9_signal_audit_acceptance.py',pathlib.Path(__file__).resolve(),root/'tests/dc_parity_release_six_host_acceptance.py',root/'tests/runtime_http_acceptance.py',root/'tests/dc_successor_contract.py',root/'deploy/mcp_tool_contract.py']
expected_old={'host_health_acceptance.py':'73f1105414b5362ab007843b4138ac7dc3bb43766630da7f70406283705cd5ea','multi_read_six_host_acceptance.py':'55b91cc2ef6207e0f23eefd3584a890621e8bf075926aa676f3b79debaf35f57','dc_functional_v9_signal_audit_acceptance.py':pin_args.expected_signal_harness_sha256}
paths.extend(root/relative for relative in PREIMPORT_PINS if root/relative not in paths)
def seals():return {p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths}
before=seals()
expected_old.update({
 'dc_functional_v9_health_multiread_acceptance.py':pin_args.expected_health_harness_sha256,
 'dc_parity_release_six_host_acceptance.py':'f9ec9fdeb9a5aaa77cb6f813aa7afe4dd3db24f199731a20d579f687c3883227',
 'runtime_http_acceptance.py':pin_args.expected_http_helper_sha256,
 'dc_successor_contract.py':pin_args.expected_loader_sha256,
 'mcp_tool_contract.py':pin_args.expected_tool_helper_sha256,
})
for name,pin in expected_old.items():assert before[name]['sha256']==pin
old_multi=paths[2]
class Offline(unittest.TestCase):
 def healthy(self,name='main'):
  return {'schema':'hepta-host-health-v1','host':name,'platform':'macos' if name=='mac' else 'linux','transport':'ssh','status':'healthy','reachable':True,'authenticated':True,'ssh_roundtrip_ms':1.25,'timeout_ms':10000,'measurement':H.MEASUREMENT,'diagnostics_redacted':True}
 def transport(self,bad_id=None,status=200,oversize=False,duplicate=False):
  records=[];owner=self
  class Connection:
   def __init__(self,host,port=None,**kw):
    owner.assertEqual((host,port),('127.0.0.1',12007));owner.assertEqual(kw,{'timeout':35})
   def request(self,method,path,body=None,headers=None):
    owner.assertEqual((method,path),('POST','/mcp'));self.q=json.loads(body);records.append(copy.deepcopy(self.q))
    owner.assertEqual(headers['X-Hepta-Runtime-Token'],'offline-mock-token')
   def getresponse(self):
    q=self.q
    class Response:
     def __init__(self):self.status=status
     def getheader(self,key):return 'offline-fixed-session' if key.lower()=='mcp-session-id' else None
     def read(self,limit):
      owner.assertEqual(limit,H.MAX_RESPONSE+1)
      if oversize:return b'x'*(H.MAX_RESPONSE+1)
      if 'id' not in q:return b''
      ident=True if bad_id=='bool' else q['id']+1 if bad_id=='other' else q['id']
      result={'content':[{'type':'text','text':'{"observed":true}'}]}
      row={'jsonrpc':'2.0','id':ident,'result':result}
      if duplicate:return ('data: '+json.dumps(row)+'\n\ndata: '+json.dumps(row)+'\n\n').encode()
      return json.dumps(row).encode()
    return Response()
   def close(self):pass
  return Connection,records
 def test_exact_healthy_linux_and_mac_schema_is_accepted(self):
  for name in ('main','mac'):
   value=self.healthy(name);self.assertIs(H.validate_health(name,value),value)
   self.assertEqual(set(value),H.HEALTH_KEYS);self.assertEqual(len(value),11)
 def test_all_valid_nonhealthy_states_remain_distinct_from_schema_failure(self):
  for state in ('timeout','ssh_failed','transport_error','invalid_response'):
   value={**self.healthy(),'status':state,'reachable':False,'authenticated':False,'ssh_roundtrip_ms':15000.5}
   observed=H.safe_health_observation('main',value)
   self.assertEqual(observed['status'],state);self.assertTrue(observed['schema_fields_exact'])
   with self.subTest(state=state),self.assertRaises(H.UnhealthyHostError):H.validate_health('main',value)
 def test_missing_and_extra_fields_are_protocol_errors(self):
  value=self.healthy()
  for key in H.HEALTH_KEYS:
   malformed={k:v for k,v in value.items() if k!=key}
   with self.subTest(missing=key),self.assertRaises(H.HealthSchemaError):H.validate_health('main',malformed)
  with self.assertRaises(H.HealthSchemaError):H.validate_health('main',{**value,'stderr':'private-payload'})
 def test_fixed_schema_host_platform_transport_and_measurement_are_exact(self):
  for field,bad in [('schema','wrong'),('host','other'),('platform','macos'),('transport','http'),('measurement',H.MEASUREMENT+' private-payload')]:
   with self.subTest(field=field),self.assertRaises(H.HealthSchemaError):H.validate_health('main',{**self.healthy(),field:bad})
 def test_status_field_rejects_unknown_and_unhashable_values(self):
  for state in ('success',None,[],{},True,1):
   with self.subTest(state=state),self.assertRaises(H.HealthSchemaError):H.validate_health('main',{**self.healthy(),'status':state})
 def test_boolean_fields_require_exact_types(self):
  for field in ('reachable','authenticated','diagnostics_redacted'):
   for invalid in (1,0,'true',None):
    with self.subTest(field=field,value=invalid),self.assertRaises(H.HealthSchemaError):H.validate_health('main',{**self.healthy(),field:invalid})
 def test_timeout_is_exact_integer_10000(self):
  for invalid in (10000.0,True,False,'10000',9999,10001,None):
   with self.subTest(value=invalid),self.assertRaises(H.HealthSchemaError):H.validate_health('main',{**self.healthy(),'timeout_ms':invalid})
 def test_reachability_and_authentication_match_typed_status(self):
  for status,reach,auth in [('healthy',False,True),('healthy',True,False),('ssh_failed',True,False),('timeout',False,True)]:
   with self.subTest(status=status),self.assertRaises(H.HealthSchemaError):H.validate_health('main',{**self.healthy(),'status':status,'reachable':reach,'authenticated':auth})
 def test_elapsed_metric_rejects_boolean_nonfinite_negative_and_bad_types(self):
  for elapsed in (True,False,math.nan,math.inf,-math.inf,-.001,'1',None,[],{}):
   with self.subTest(elapsed=elapsed),self.assertRaises(H.HealthMetricError):H.validate_health('main',{**self.healthy(),'ssh_roundtrip_ms':elapsed})
 def test_healthy_elapsed_upper_bound_is_strict(self):
  H.validate_health('main',{**self.healthy(),'ssh_roundtrip_ms':10999.999})
  for elapsed in (11000,11000.001,999999):
   with self.subTest(elapsed=elapsed),self.assertRaises(H.HealthMetricError):H.validate_health('main',{**self.healthy(),'ssh_roundtrip_ms':elapsed})
 def test_safe_observation_discards_extra_payloads_and_unhashable_string_fields(self):
  value={**self.healthy(),'status':['private-status'],'schema':{'secret':'private-schema'},'stderr':'private-stderr','measurement':'private-measurement'}
  observed=H.safe_health_observation('main',value);rendered=json.dumps(observed,allow_nan=False)
  for secret in ('private-status','private-schema','private-stderr','private-measurement'):self.assertNotIn(secret,rendered)
  self.assertEqual(observed['status'],'unexpected');self.assertEqual(observed['schema'],'unexpected');self.assertFalse(observed['schema_fields_exact'])
  self.assertEqual(observed['response_sha256'],hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest())
 def test_safe_observation_nonfinite_values_never_produce_invalid_json(self):
  for elapsed in (math.nan,math.inf,-math.inf,True,'private-metric'):
   observed=H.safe_health_observation('main',{**self.healthy(),'ssh_roundtrip_ms':elapsed})
   self.assertIsNone(observed['ssh_roundtrip_ms']);json.dumps(observed,allow_nan=False)
 def test_nondict_health_response_is_safe_summary_and_schema_failure(self):
  for value in (None,['private-array'],'private-string',True):
   observed=H.safe_health_observation('main',value)
   self.assertNotIn('private-',json.dumps(observed));self.assertFalse(observed['schema_fields_exact'])
   with self.assertRaises(H.HealthSchemaError):H.validate_health('main',value)
 def test_direct_loopback_does_not_consult_proxy_settings(self):
  connection,records=self.transport()
  with mock.patch.object(H.http.client,'HTTPConnection',connection),mock.patch.dict(os.environ,{'HTTP_PROXY':'http://proxy.invalid','HTTPS_PROXY':'http://proxy.invalid','ALL_PROXY':'http://proxy.invalid','NO_PROXY':''}):
   client=H.StrictReadClient(12007,'offline-mock-token')
   self.assertEqual(client.call('host_health',{'host':'main'}),{'observed':True});client.close()
  self.assertIsNone(client._token);self.assertIsNone(client._session)
  self.assertEqual([row['method'] for row in records],['initialize','notifications/initialized','tools/call'])
 def test_client_denies_mutating_tools_without_http_submission(self):
  connection,records=self.transport()
  with mock.patch.object(H.http.client,'HTTPConnection',connection):
   client=H.StrictReadClient(12007,'offline-mock-token');before=len(records)
   for tool in ('host_signal','process_start','process_cancel','pty_write','text_editor'):
    with self.subTest(tool=tool),self.assertRaises(ValueError):client.call(tool,{})
    self.assertEqual(len(records),before)
   with self.assertRaises(ValueError):client.rpc('notifications/cancelled',{})
   self.assertEqual(len(records),before);client.close()
 def test_client_rejects_bool_or_wrong_rpc_id_without_retry(self):
  for bad in ('bool','other'):
   connection,records=self.transport(bad_id=bad)
   with self.subTest(id=bad),mock.patch.object(H.http.client,'HTTPConnection',connection):
    with self.assertRaises(ValueError):H.StrictReadClient(12007,'offline-mock-token')
   self.assertEqual(len(records),1)
 def test_client_rejects_redirect_oversize_and_duplicate_response_without_retry(self):
  for options in ({'status':302},{'oversize':True},{'duplicate':True}):
   connection,records=self.transport(**options)
   with self.subTest(options=options),mock.patch.object(H.http.client,'HTTPConnection',connection):
    with self.assertRaises(ValueError):H.StrictReadClient(12007,'offline-mock-token')
   self.assertEqual(len(records),1)
 def test_population_uses_same_nonce_guard_and_exact_old_data_without_new_mkdtemp(self):
  item=F.planned_fixture('main',dict(F.HOSTS)['main'],'a'*32);item.update(uid=1000,prepare_attempted=True,prepare_confirmed=True)
  tree=ast.parse(old_multi.read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='create_fixture')
  call=next(n for n in ast.walk(fn) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='target_python')
  old_source=ast.literal_eval(call.args[1]);old_tree=ast.parse(old_source)
  text=next(ast.literal_eval(n.value) for n in old_tree.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='text')
  result={'base':item['base'],'root':item['root'],'text':text,'sha256':hashlib.sha256(text.encode()).hexdigest()}
  with mock.patch.object(F,'target_python',return_value=result) as remote:
   fixture=H.populate_multiread(item['ssh_target'],item,F,old_multi)
   self.assertEqual(remote.call_count,1);source=remote.call_args.args[1]
  parsed=ast.parse(source);self.assertTrue(source.startswith(F.fixture_guard(item)))
  self.assertEqual(fixture['base'],item['base']);self.assertEqual(fixture['nonce'],item['nonce']);self.assertEqual(fixture['text'],text)
  self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='mkdtemp' for n in ast.walk(parsed)))
  base_assignments=[n for n in parsed.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='base']
  self.assertEqual(len(base_assignments),1);self.assertEqual(ast.literal_eval(base_assignments[0].value.args[0]),item['base'])
  guard_line=next(n.lineno for n in ast.walk(parsed) if isinstance(n,ast.Compare) and isinstance(n.left,ast.Name) and n.left.id=='ownership')
  writes=[n.lineno for n in ast.walk(parsed) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in {'write_bytes','write_text','mkdir','symlink_to','link','mkfifo'}]
  self.assertTrue(writes);self.assertLess(guard_line,min(writes))
  transformed=[]
  for line in old_source.splitlines():
   if line.startswith('base=pathlib.Path'):continue
   if line.startswith("root=base/'workspace';root.mkdir"):line="root=base/'workspace'"
   transformed.append(line)
  self.assertTrue(source.endswith('\n'+'\n'.join(transformed)+'\n'))
 def test_population_wrong_ack_is_not_adopted_or_retried(self):
  item=F.planned_fixture('main',dict(F.HOSTS)['main'],'a'*32);item.update(uid=1000,prepare_attempted=True,prepare_confirmed=True)
  original=copy.deepcopy(item)
  result={'base':item['base'],'root':item['root'],'text':'fixture','sha256':hashlib.sha256(b'fixture').hexdigest()}
  for field,bad in [('base','/wrong'),('root','/wrong'),('sha256','0'*64)]:
   with self.subTest(field=field),mock.patch.object(F,'target_python',return_value={**result,field:bad}) as remote:
    with self.assertRaises(ValueError):H.populate_multiread(item['ssh_target'],item,F,old_multi)
    self.assertEqual(remote.call_count,1);self.assertEqual(item,original)
 def test_population_lost_ack_never_repeats_create_or_changes_reference(self):
  item=F.planned_fixture('main',dict(F.HOSTS)['main'],'a'*32);item.update(uid=1000,prepare_attempted=True,prepare_confirmed=True)
  original=copy.deepcopy(item)
  with mock.patch.object(F,'target_python',side_effect=F.TargetOperationError('TimeoutExpired')) as remote:
   with self.assertRaises(F.TargetOperationError):H.populate_multiread(item['ssh_target'],item,F,old_multi)
   self.assertEqual(remote.call_count,1);self.assertEqual(item,original)
 def test_pinned_old_qualify_host_ast_is_exactly_unchanged(self):
  old_module=H.import_pinned('offline_old_multiread',old_multi,expected_old[old_multi.name])
  old_fn=next(n for n in ast.parse(old_multi.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='qualify_host')
  imported_fn=ast.parse(inspect.getsource(old_module.qualify_host)).body[0]
  self.assertEqual(ast.dump(old_fn,include_attributes=False),ast.dump(imported_fn,include_attributes=False))
  module=ast.parse(paths[0].read_text())
  calls=[n for n in ast.walk(module) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='qualify_host']
  self.assertEqual(len(calls),1);self.assertEqual(ast.unparse(calls[0].func),'multi.qualify_host')
 def test_health_observation_is_saved_before_validation_and_each_selected_call_is_once(self):
  tree=ast.parse(paths[0].read_text())
  loops=[n for n in ast.walk(tree) if isinstance(n,ast.For) and isinstance(n.target,ast.Tuple) and
   [e.id for e in n.target.elts if isinstance(e,ast.Name)]==['name','_'] and isinstance(n.iter,ast.Name) and n.iter.id=='selected']
  health_loop=next(n for n in loops if any(isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id=='validate_health' for x in ast.walk(n)))
  validations=[n.lineno for n in ast.walk(health_loop) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='validate_health']
  observations=[n.lineno for n in ast.walk(health_loop) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='safe_health_observation']
  saves=[n.lineno for n in ast.walk(health_loop) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='save']
  self.assertEqual(len(validations),1);self.assertEqual(len(observations),1)
  self.assertLess(observations[0],validations[0]);self.assertTrue(any(observations[0]<=line<validations[0] for line in saves))
  calls=[n for n in ast.walk(health_loop) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='call' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='host_health']
  self.assertEqual(len(calls),1);self.assertFalse(any(isinstance(n,(ast.While,ast.For)) for n in ast.walk(health_loop) if n is not health_loop))
 def test_reconnect_has_success_guard_and_failed_initial_health_is_never_replayed(self):
  tree=ast.parse(paths[0].read_text())
  parent={}
  for node in ast.walk(tree):
   for child in ast.iter_child_nodes(node):parent[child]=node
  calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and
   isinstance(n.func.value,ast.Name) and n.func.value.id=='reconnect' and n.func.attr=='call']
  self.assertEqual(len(calls),1)
  ancestors=[];node=calls[0]
  while node in parent:node=parent[node];ancestors.append(node)
  guards=[n for n in ancestors if isinstance(n,ast.If)]
  self.assertTrue(any('all(' in ast.unparse(n.test) and 'complete' in ast.unparse(n.test) for n in guards))
  constants=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
  self.assertTrue(any('reconnect' in value and ('skip' in value or 'failed' in value) for value in constants))
 def test_all_old_input_hashes_are_frozen(self):
  for name,pin in expected_old.items():self.assertEqual(seals()[name]['sha256'],pin)
def main():
 result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(Offline))
 after=seals()
 print('OFFLINE_AUDIT',json.dumps({'before':before,'after':after,'stable':before==after,'cases':result.testsRun,'no_health_ssh_native_or_controllers_executed':True,'candidate_version':9,'original_v8_loader_provenance':ORIGINAL_V8_LOADER_PROVENANCE,'prior_V8_tests_or_native_results_borrowed':False,'explicit_preimport_pins':PREIMPORT_PINS},sort_keys=True))
 raise SystemExit(0 if result.wasSuccessful() and before==after else 1)

if __name__=='__main__':
 main()
