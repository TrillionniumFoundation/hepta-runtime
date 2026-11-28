from pathlib import Path
import os,sys,json,time,hashlib,unittest,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import load
P,R,O,public,elf,elf_sha=load('catalog_component',create=False)
build=Path(public['catalog_build'])
if O.exists():raise ValueError('fresh exact catalog evidence required')
os.environ['HIA_FULL_CATALOG_BUILD']=str(build)
os.environ['HIA_FULL_CATALOG_EVIDENCE']=str(O)
sys.path.insert(0,str(R/'tests/hia_native'))
import test_full_catalog_capability as module
cls=module.FullCatalogTests
expected=["test_01_complete_136_input_all_18_policy_shapes_and_actual_flags1_wires","test_02_retained_operations_preserve_entire_return_output_workspace","test_03_invalid_queries_short_outputs_and_workspace_growth_do_not_publish","test_04_exact_final_output_capacity_and_legacy_present_flags","test_05_native_owner_emits_complete_declaration_frame_and_refuses_bad_child_headers","test_06_independent_simultaneous_calls_share_only_sealed_code"]
actual=unittest.defaultTestLoader.getTestCaseNames(cls)
if actual!=expected:raise ValueError('complete six original method names differ')
started=time.monotonic()
result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
counts={'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),'isolated':sys.flags.isolated,'optimize':sys.flags.optimize}
ok=(counts['tests_run']==6 and all(counts[k]==0 for k in ('failures','errors','skipped','expected_failures','unexpected_successes','optimize')) and counts['isolated']==1 and result.wasSuccessful())
details=getattr(cls,'assertions',{})
ok=ok and len(details.get('rows',[]))==18 and details.get('old_comparisons')==187 and details.get('malformed_queries')==19 and details.get('capacity_controls')==12 and details.get('owner_controls')==12
record={'schema':'hepta.runtime.public-full-catalog.exact-complete-suite.v1','status':'PASS'if ok else'FAIL',**counts,'expected_method_names':expected,'seconds':time.monotonic()-started,'build':getattr(cls,'build_pin',{}),'details':details,'source_before':getattr(cls,'source_before',{}),'source_after':getattr(cls,'source_after',{}),'artifact_before':getattr(cls,'artifact_before',{}),'artifact_after':getattr(cls,'artifact_after',{}),'original_rust_processes_started':0,'original_216_rust_handler_cases_rerun':False,'public_tools_list_wire_qualified':False,'whole_runtime_replaced':False}
if not O.exists():O.mkdir()
(O/'result.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:record[k]for k in ('status','tests_run','failures','errors','skipped','expected_failures','unexpected_successes','isolated','optimize','seconds')},sort_keys=True),flush=True)
raise SystemExit(0 if ok else 1)
