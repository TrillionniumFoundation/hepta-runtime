from pathlib import Path
import hashlib,json,sys,subprocess
repo=Path('/home/qian-qi/work/hepta-rea-family-ecb0b9d61c75-20261106')
root=Path(str(repo)+'-evidence/elf-family-r1')
out=Path(str(repo)+'-evidence/c9-catalog-audit-r1')
sys.path.insert(0,str(repo/'scripts'))
import rea_operation_qualification as q
import rea_elf_evidence_family_evidence as f
import rea_compatibility_ledger as l
assert subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()=='c9c79e27a2bf56bd204df6591ca2311dc872e317'
raw=(root/'qualification.json').read_bytes()
receipt_sha=hashlib.sha256(raw).hexdigest()
assert receipt_sha=='f9507225345b65491cfb05f3a280eae2a9c04278b28d624035955efac24a1047'
report=q.parse_json(raw)
source,binding=f.verify_identity_and_source(repo,root,report)
fixtures,workspace=f.verify_fixtures(root,report)
sessions={label:f.ReplaySession(root,label,'producer',report['sessions'][label+'/producer'],report,workspace) for label in ('reference','native')}
stored=l.read_json(repo/l.LEDGER_PATH)
snapshot=l.snapshot_rows(stored['tools'])
assert l.digest_json(snapshot)==f.CATALOG_SNAPSHOT
wanted=sorted(snapshot,key=lambda row:row['catalog_index'])
original=sessions['reference'].tools
assert len(original)==229 and len({row['name'] for row in original})==229
actual_by_name={row['name']:row for row in original}
rows=[]
for row in wanted:
    name=row['upstream_tool']; actual=actual_by_name.get(name)
    actual_input=None if actual is None else q.digest(actual.get('inputSchema'))
    actual_output=None if actual is None else q.digest(actual.get('outputSchema'))
    fp=row['schema_fingerprints']
    checks={'present':actual is not None,'full_input_schema':actual_input==fp['full_input'],'full_output_schema':actual_output==fp['full_output'],'annotations':actual is not None and q.json_equal(actual.get('annotations',{}),row['upstream_annotations'])}
    rows.append({'name':name,'catalog_index':row['catalog_index'],'checks':checks,'actual_input_sha256':actual_input,'expected_input_sha256':fp['full_input'],'actual_output_sha256':actual_output,'expected_output_sha256':fp['full_output'],'status':'PASS' if all(checks.values()) else 'DIFF'})
name_order=[row['name'] for row in original]==[row['upstream_tool'] for row in wanted]
mapping=l.read_json(repo/l.MAP_PATH)
runtime=l.runtime_inventory(repo,mapping)
native=sorted(row['name'] for row in sessions['native'].tools if row['name'].startswith('rea_'))
native_match=native==runtime['interfaces']
complete=name_order and native_match and len(rows)==229 and all(row['status']=='PASS' for row in rows)
result={'schema':'hepta.rea.captured-catalog-audit.v1','status':'PASS' if complete else 'DIFF','qualified':False,'scope':'Exact captured names/order, full input/output schema fingerprints and annotations for all 229 original tools, plus captured native REA interface names; no behavioral, Git/npm equivalence or complete P0 qualification. Descriptions and titles are retained in original tools artifacts but not compared to the ledger.','source_commit':'c9c79e27a2bf56bd204df6591ca2311dc872e317','source_tree_sha256':source['tree_sha256'],'family_receipt_sha256':receipt_sha,'build_summary_sha256':binding['build_summary_sha256'],'binary_sha256':report['binary_before']['sha256'],'reference':report['reference_before'],'catalog_snapshot_sha256':f.CATALOG_SNAPSHOT,'catalog_profile':{'input':'full','output':'full'},'original_tool_count':len(original),'original_name_order_equal':name_order,'passed_contracts':sum(row['status']=='PASS' for row in rows),'diff_contracts':sum(row['status']!='PASS' for row in rows),'rows':rows,'native_rea_interface_count':len(native),'native_rea_names':native,'native_names_equal_source_inventory':native_match,'original_artifacts':{label:{name:report['sessions'][label+'/producer'][name] for name in ('tools','wire_index','launch','close_artifact')} for label in ('reference','native')},'producer':q.identity(Path(__file__)),'consumer_sources':[q.identity(repo/'scripts'/name) for name in ('rea_elf_evidence_family_evidence.py','rea_operation_evidence.py','rea_operation_qualification.py','rea_compatibility_ledger.py')]}
out.mkdir()
p=out/'assessment.json';q.write_json(p,result)
print(json.dumps({'status':result['status'],'qualified':False,'original_tool_count':len(original),'passed_contracts':result['passed_contracts'],'diff_contracts':result['diff_contracts'],'original_name_order_equal':name_order,'native_rea_interface_count':len(native),'native_names_equal_source_inventory':native_match,'assessment':q.identity(p)},sort_keys=True))
raise SystemExit(0 if complete else 1)
