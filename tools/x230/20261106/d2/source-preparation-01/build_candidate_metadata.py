from pathlib import Path
import ast,difflib,hashlib,json,os,re
ROOT=Path("/tmp/hepta-runtime-recovery-20261106/d2-source-preparation-01")
def identity(raw):
 return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def create(name,raw):
 path=ROOT/name
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 with path.open("xb") as handle:
  handle.write(raw);handle.flush();os.fsync(handle.fileno())
 assert path.read_bytes()==raw
 return identity(raw)
def canonical(value):
 return (json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)+"\n").encode()
paths=["src/mcp/runtime/phase_cost.rs","src/mcp/runtime/ssh_observation_profile.rs"]
old={path:(ROOT/"references"/Path(path).name).read_bytes() for path in paths}
new={path:(ROOT/"source"/path).read_bytes() for path in paths}
baseline_raw=(ROOT/"baseline-source-map.json").read_bytes()
candidate_raw=(ROOT/"candidate-source-map.json").read_bytes()
baseline=json.loads(baseline_raw);candidate=json.loads(candidate_raw)
assert len(baseline)==len(candidate)==222 and baseline.keys()==candidate.keys()
assert sorted(path for path in baseline if baseline[path]!=candidate[path])==paths
for path in paths:
 assert identity(old[path])["sha256"]==baseline[path]
 assert identity(new[path])["sha256"]==candidate[path]
profile_path=paths[1];profile=new[profile_path].decode()
pattern=r'(?m)^\t\t#\[cfg\(all\(feature = "phase-cost-diagnostics", target_os = "linux"\)\)\]\n\t\t(?:let\b[\s\S]*?;\n|drop\([^;\n]*\);\n)'
removed=re.findall(pattern,profile)
assert len(removed)==9
assert re.sub(pattern,"",profile).encode()==old[profile_path]
assert sum("let " in value for value in removed)==6
assert sum("drop(" in value for value in removed)==3
assert all("await" not in value for value in removed)
assert all("phase_cost" in value or "drop(diagnostic_file_" in value for value in removed)
new_enum="\tBinding,\n\tFileChecked,\n\tFileReadReference,\n\tFileReadHash,\n\tFileFinalCheck,\n\tFileIdentity,\n\tShellResolution,\n\tProfilePolicy,\n}"
phase=new[paths[0]].decode()
assert phase.count(new_enum)==1
restored=phase.replace(new_enum,"\tBinding,\n}").replace("const EVENT_CAPACITY: usize = 131_072;","const EVENT_CAPACITY: usize = 32_768;").replace('"preparation_revision": "validation-cost-d2-01"','"preparation_revision": "recovery-02"')
assert restored.encode()==old[paths[0]]
parser=(ROOT/"summarize_trace_d2.py").read_bytes()
original_parser=(ROOT/"references/summarize_trace_d1.py").read_bytes()
ast.parse(parser);ast.parse(original_parser)
assert parser.decode().replace("131072","32768").replace("131071","32767").replace('"preparation_revision": "validation-cost-d2-01"','"preparation_revision": "recovery-02"').encode()==original_parser
patch="".join("".join(difflib.unified_diff(old[path].decode().splitlines(keepends=True),new[path].decode().splitlines(keepends=True),fromfile="a/"+path,tofile="b/"+path,n=3)) for path in paths).encode()
patch_id=create("candidate.patch",patch)
inputs={
 "schema":"hepta-x230-d2-candidate/v1",
 "candidate":"D2",
 "purpose":"diagnostic-only validation phase decomposition; no runtime optimization or adoption claim",
 "baseline_commit":"8eb1a0af7a85768e374717d24848fd9798871cc9",
 "git_parent":"8eb1a0af7a85768e374717d24848fd9798871cc9",
 "qualified_d1_source_commit":"9172f6112aa9fc269625ae963d666ed34c534e01",
 "accepted_production_baseline_commit":"baab4def80be7af015b2e7a594cb302f66c4130e",
 "root":"/home/qian/hepta-runtime-validation-cost-20261106-d2",
 "baseline_compile_inputs":baseline,
 "candidate_compile_inputs":candidate,
 "changed_paths":paths,
 "added_paths":[],
 "removed_paths":[],
 "new_test_functions":[],
 "source_files":{path:identity(new[path]) for path in paths},
 "baseline_changed_file_originals":{path:identity(old[path]) for path in paths},
 "baseline_source_map":identity(baseline_raw),
 "candidate_source_map":identity(candidate_raw),
 "candidate_patch":patch_id,
 "derived_parser":{"path":"summarize_trace_d2.py",**identity(parser),"source_original":identity(original_parser),"capacity_literal_edits":3,"revision_literal_edits":1,"executed":False},
 "protocol":{"original_eight_qualification_stages":True,"original_nineteen_harness_tools":True,"jobs":2,"disk_floor_bytes":3*1024**3,"ordinary_feature_off_cfg_erasure":True,"same_feature_elf_for_off_and_on":True,"diagnostic_only":True,"event_capacity":131072,"request_capacity":2048,"output_limit":32*1024**2,"fail_on_drop_unchanged":True,"per_chunk_instrumentation":False,"native_auditor_unchanged":True,"runtime_adoption":False},
 "actual_qualification_job_id":None,
 "actual_qualification_report":None,
 "actual_qualification_counts":None,
 "actual_formatted_source_map":None,
 "prepared_source_state":{"formatted":False,"compiled":False,"rust_tests_executed":False,"diagnostic_executed":False,"host_calls":0}
}
input_id=create("input.json",canonical(inputs))
checks={
 "schema":"hepta-d2-source-static-checks/v1",
 "baseline_map":identity(baseline_raw),
 "candidate_map":identity(candidate_raw),
 "actual_git_originals_equal_qualified_d1_map":True,
 "both_maps_exact_222_keys":True,
 "only_two_source_paths_changed":paths,
 "profile_cfg_statement_count":len(removed),
 "profile_synchronous_guards":6,
 "profile_success_boundary_drops":3,
 "profile_after_cfg_erasure_byte_equal_original":True,
 "old_check_current_questionmark_loop_and_error_order_byte_preserved":True,
 "new_guard_statements_have_no_await":True,
 "conditional_loop_label_in_cfg_statement_only":True,
 "phase_cost_inverse_three_deltas_byte_equal_original":True,
 "event_record_fields_slots_ownership_and_output_writer_unchanged":True,
 "parser_inverse_capacity_and_revision_only_byte_equal_original":True,
 "parser_ast_parsed_without_import":True,
 "new_rust_tests":[],"rust_tools_run":False,"target_source_or_parser_executed":False,"remote_calls":0,
 "source_identities":{path:identity(new[path]) for path in paths},"candidate_patch":patch_id,"input":input_id,
 "future_qualification_counts_not_claimed":True
}
checks_id=create("STATIC_CHECKS.json",canonical(checks))
print(json.dumps({"source":checks["source_identities"],"patch":patch_id,"input":input_id,"static_checks":checks_id,"parser":identity(parser),"baseline_map":identity(baseline_raw),"candidate_map":identity(candidate_raw)},indent=2))
