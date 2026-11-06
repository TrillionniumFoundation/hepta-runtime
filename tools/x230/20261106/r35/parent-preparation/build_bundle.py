#!/usr/bin/env python3
"""Prepare R35 parent/normal lifecycle sources without executing any campaign."""
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import re

BASE=Path('/tmp/hepta-runtime-recovery-20261106')
REF=BASE/'r34-observation-template-01'
PREP=BASE/'r35-qualification-prep-01/sealed-01'
OUT=BASE/'r35-observation-template-01'
OLD_ROOT='/home/qian/hepta-runtime-optimization-20261106-r34'
ROOT='/home/qian/hepta-runtime-optimization-20261106-r35'
PREPARER_SHA='6870655895432c8bd3ca266d00eb4a68b3150619352306c997a81ca0487130f4'
INPUT_SHA='652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63'
OWNER_SHA='2bc6f84cc6f26b8f10306b8a7310f21e64b52b6c3a2a86f7191bc239801dcd47'
MANIFEST_SHA='93322bccec1743b9a4734e0ea51b6aa87fabd7f73a64147a0102ec4cc31eb93a'
HOLDER_SHA='715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'
CHANGED={'src/mcp/runtime/jobs.rs','src/mcp/runtime/ssh_observation_pool.rs',
         'src/mcp/runtime/ssh_observation_pool_tests.rs'}
SCOPE='accepted R24 plus legacy-read JSON deferral and observation command ownership move; three frozen source files'
PROPOSAL='R24 plus legacy-read JSON deferral and observation command move; three frozen files only'

def need(ok,why):
    if not ok: raise ValueError(why)

def ident(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def canonical(x):return (json.dumps(x,indent=2,sort_keys=True)+'\n').encode()
def tree(t):return ast.dump(ast.parse(t),include_attributes=False)
def functions(t):return {n.name:n for n in ast.parse(t).body if isinstance(n,ast.FunctionDef)}
def segment(t,n):return ast.get_source_segment(t,functions(t)[n])
def rename(t):return t.replace(OLD_ROOT,ROOT).replace('r34','r35').replace('R34','R35').replace('"h34"','"h35"')
def normalize(t):return t.replace(ROOT,OLD_ROOT).replace('r35','r34').replace('R35','R34').replace('"h35"','"h34"')
def once(t,a,b):
    need(t.count(a)==1,'unique transform required: '+a[:100]);return t.replace(a,b,1)
def assigned(t,name):
    nodes=[n for n in ast.parse(t).body if isinstance(n,ast.Assign) and len(n.targets)==1
           and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    need(len(nodes)==1,'assignment: '+name);return nodes[0]
def set_assignment(t,name,value):
    n=assigned(t,name);lines=t.splitlines(keepends=True)
    lines[n.lineno-1:n.end_lineno]=[name+' = '+pprint.pformat(value,sort_dicts=True)+'\n']
    return ''.join(lines)
def create(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def make_binder(original):
    text=rename(original)
    text=set_assignment(text,'R35_CHANGED_PATHS',CHANGED)
    text=set_assignment(text,'R35_ADOPTION_SCOPE',SCOPE)
    text=set_assignment(text,'R35_OPEN_BLOCKERS',[])
    text=once(text,'R24 plus ordinary-first existing-job cancellation reserve; four frozen files only',PROPOSAL)
    text=text.replace('four selected source and test files','three selected source and test files')
    text=text.replace('four-file R24 ablation','three-file R24 ablation')
    text=text.replace('outside the four selected files','outside the three selected files')
    text=once(text,'ordinary-first existing-job cancellation reserve on accepted R24',
              'legacy-read JSON deferral and observation command ownership move on accepted R24')
    text=once(text,'"bytes": 3707,','"bytes": 3742,')
    text=once(text,'7065ad29178dbec61a1ed78fa24c9697cd6b6d3fed1ca9d5bb6cb7335b097e1e',INPUT_SHA)
    text=once(text,'"bytes": 29912,','"bytes": 32838,')
    text=once(text,'6f50859c6155ecc1c0eea78a027ae94508d6de9dee0545cef00bde8fee0bf67f',PREPARER_SHA)
    need(re.search(r'\breserve\b',text) is None and 'four-file' not in text and 'four selected' not in text,'R34 candidate scope leaked')
    return text

OWNER_HEAD='''R35_CACHE_OWNER = Path("/home/qian/hepta-runtime-optimization-20261106-r34")
R35_CACHE_OWNER_CLOSURE = {
    "path": str(ROOT / "cache-owner-closure-inputs.json"), "bytes": 5378,
    "sha256": "2bc6f84cc6f26b8f10306b8a7310f21e64b52b6c3a2a86f7191bc239801dcd47",
}


def r35_relative_identity(value):
    relative = Path(value["path"])
    need(not relative.is_absolute() and ".." not in relative.parts, "unsafe R35 frozen member")
    return {**value, "path": str(ROOT / relative)}


def bind_r35_chain_and_cache_owner(preparation, build_inputs, bind):
    """Bind R24-plus-R35 source and the rejected, closed R34 cache owner separately."""
    def document(identity):
        return json.loads(bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1])
    expected_input = r35_relative_identity(build_inputs["candidate_input"])
    expected_manifest = r35_relative_identity(build_inputs["candidate_manifest"])
    need(preparation["frozen_candidate_input"] == expected_input
         and preparation["frozen_candidate_manifest"] == expected_manifest
         and preparation["source_materialization"]
         == "accepted R24 source copy plus the frozen R35 patch; R34 supplies build cache only",
         "R35 source provenance differs")
    candidate, patch = r35_frozen_candidate(build_inputs, bind)
    need(preparation["candidate_patch"] == patch, "frozen three-file patch differs")
    closure_id = R35_CACHE_OWNER_CLOSURE
    need(preparation["cache_owner_closure_input"] == closure_id
         and build_inputs["owner_closure_input_sha256"] == closure_id["sha256"],
         "actual R34 cache-owner receipt differs")
    owner = r35_cache_owner_closed(document(closure_id), build_inputs["qualification_harness_sha256"], bind)
    need(preparation["cache_owner_closure"] == owner, "preparer and parent owner-closure results differ")
    return {"source_baseline_commit": R35_BASELINE_COMMIT,
        "frozen_candidate_input": expected_input, "frozen_candidate_manifest": expected_manifest,
        "candidate_patch": patch, "changed_paths": sorted(R35_CHANGED_PATHS),
        "cache_owner_closure": closure_id, "cache_owner_proof": owner,
        "r34_source_used_as_baseline": False, "r34_performance_adopted": False,
        "cache_deletion_scope": "the R35 preparer deletes zero files and transfers only the closed R34 build cache by rename",
        "current_machine_idle_claimed": False, "original_auditors_reexecuted": False}


'''

NAMES=('native_terminal','closed_stages','completed_qualification','native_streams','frozen_candidate','cache_owner_closed')
RENAMES=(('native_terminal','r35_owner_native_terminal'),('closed_stages','r35_owner_closed_stages'),
         ('completed_qualification','r35_owner_completed_qualification'),('native_streams','r35_owner_native_streams'),
         ('frozen_candidate','r35_frozen_candidate'),('cache_owner_closed','r35_cache_owner_closed'),
         ('relative_identity','r35_relative_identity'),('CACHE_OWNER','R35_CACHE_OWNER'),
         ('BASELINE_COMMIT','R35_BASELINE_COMMIT'),('CHANGED','R35_CHANGED_PATHS'),('STAGES','R35_QUALIFICATION_STAGES'))

def make_owner(preparer):
    blocks=[]
    for name in NAMES:
        text=segment(preparer,name)
        for a,b in RENAMES:text=re.sub(r'\b'+a+r'\b',b,text)
        text=text.replace('== source_map(source)','== qualification_projection(source_inputs(source))')
        if name in ('frozen_candidate','cache_owner_closed'):
            first,rest=text.split('\n',1);first=first[:-2]+', bind):'
            text=first+'\n'+'    def read_bound(identity):\n        return bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1]\n'+rest
        blocks.append(text)
    result=OWNER_HEAD+'\n\n\n'.join(blocks)+'\n\n'
    for name in NAMES:
        target=dict(RENAMES)[name];back=segment(result,target)
        if name in ('frozen_candidate','cache_owner_closed'):
            back=back.replace(', bind):','):',1)
            back=once(back,'    def read_bound(identity):\n        return bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1]\n','')
        for a,b in reversed(RENAMES):back=re.sub(r'\b'+b+r'\b',a,back)
        back=back.replace('== qualification_projection(source_inputs(source))','== source_map(source)')
        need(tree(back)==tree(segment(preparer,name)),'owner helper behavior changed: '+name)
    return result

def main():
    need(not OUT.exists(),'new output directory required')
    manifest_raw=(REF/'generated/runner-bundle-manifest.json').read_bytes()
    need(ident(manifest_raw)['sha256']==MANIFEST_SHA,'R34 bundle differs')
    old_manifest=json.loads(manifest_raw);original={}
    for name,pin in old_manifest['files'].items():
        raw=(REF/'generated'/name).read_bytes();need(ident(raw)==pin,'R34 source differs: '+name)
        original[name]=raw.decode()
    prep=(PREP/'prepare_qualify.py').read_bytes();inp=(PREP/'qualification-input.json').read_bytes();own=(PREP/'cache-owner-closure-inputs.json').read_bytes()
    need(ident(prep)=={'bytes':32838,'sha256':PREPARER_SHA},'R35 preparer differs')
    need(ident(inp)=={'bytes':3742,'sha256':INPUT_SHA},'R35 qualification input differs')
    need(ident(own)=={'bytes':5378,'sha256':OWNER_SHA},'R35 owner input differs')
    old_binder=(REF/'r34_qualification_binding.py').read_bytes()
    need(ident(old_binder)=={'bytes':16800,'sha256':'04c590d8273ef48870ba0af18d9f9099f30718b752091c51cfbd663a070a5745'},'R34 binder differs')
    binder=make_binder(old_binder.decode());owner=make_owner(prep.decode());generated={}
    for name,old in original.items():
        text=rename(old)
        if name=='r34_campaign.py':
            first,last=text.index('R35_BASELINE_COMMIT'),text.index('def commands(')
            text=text[:first]+binder+owner+'\n\n'+text[last:]
        ast.parse(text);generated[name.replace('r34','r35')]=text.encode()
    holder=(REF/'mac-launchers-01/held_agent_campaign_02.py').read_bytes()
    need(ident(holder)['sha256']==HOLDER_SHA,'original held-agent differs')
    for name in ('prepare_campaign_inputs.py','prepare_lifecycle_inputs.py','r34_lifecycle_campaign.py','install_measurement_tools.py'):
        need(normalize(generated[name.replace('r34','r35')].decode())==original[name],'nonbinder protocol changed: '+name)
    old_parent=original['r34_campaign.py'];new_parent=generated['r35_campaign.py'].decode()
    a,b=old_parent.index('R34_BASELINE_COMMIT'),old_parent.index('def commands(')
    c,d=new_parent.index('R35_BASELINE_COMMIT'),new_parent.index('def commands(')
    need(old_parent[:a]==normalize(new_parent[:c]) and old_parent[b:]==normalize(new_parent[d:]),'measurement/control bytes changed')
    unchanged=sorted(set(functions(old_parent))-set(functions(old_parent[a:b])))
    restored=functions(normalize(new_parent))
    need(all(ast.dump(functions(old_parent)[name],include_attributes=False)==ast.dump(restored[name],include_attributes=False) for name in unchanged),'measurement/control AST changed')
    files={name:ident(raw) for name,raw in sorted(generated.items())}
    qualification_inputs={name:dict(ident((PREP/name).read_bytes()),path=ROOT+'/'+name) for name in ('prepare_qualify.py','qualification-input.json','candidate/candidate.patch')}
    manifest=json.loads(rename(manifest_raw.decode()))
    manifest.update(reference_parent_tree='db9bcd9e9374497135ac37d0ead6901095c90a3d',reference_parent_bundle_sha256=MANIFEST_SHA,
                    reference_parent_sources=old_manifest['files'],preparation_launcher_sha256=PREPARER_SHA,
                    scope=SCOPE,open_blockers=[],files=files,qualification_inputs=qualification_inputs)
    manifest['private_namespaces']['observation']=['/home/qian/h35n01','/home/qian/h35b01','/home/qian/h35c01']
    need(manifest['private_namespaces']=={'observation':['/home/qian/h35n01','/home/qian/h35b01','/home/qian/h35c01'],
         'normal_lifecycle_prefix':'/home/qian/r35lc1',
         'recovery':'/home/qian/hepta-runtime-optimization-20261104-r16/r35-cancel-recovery-01'},'R35 namespace metadata differs')
    need(manifest['sealed'] is False,'future results must remain unbound')
    future=manifest['future_qualification']
    need(all(future[n] is None for n in ('native_job_id','native_terminal_sha256','preparation_sha256','qualification_report_sha256','formatted_source_map_sha256','test_counts')),'future qualification invented')
    need(all(pin['bytes'] is None and pin['sha256'] is None for pin in future['binaries'].values()),'future binary invented')
    outputs={OUT/'generated'/name:raw for name,raw in generated.items()}
    outputs[OUT/'generated/runner-bundle-manifest.json']=canonical(manifest)
    outputs[OUT/'r35_qualification_binding.py']=binder.encode();outputs[OUT/'cache_owner_binding.py']=owner.encode()
    for name in ('r35_campaign.py','r35_lifecycle_campaign.py'):outputs[OUT/'mac-launchers-01'/name]=generated[name]
    outputs[OUT/'mac-launchers-01/held_agent_campaign_02.py']=holder
    for name in ('campaign-inputs-01.example.json','lifecycle-inputs-01.example.json'):
        value=json.loads(rename((REF/name).read_text()))
        value['qualification_launcher']=qualification_inputs['prepare_qualify.py'];value['qualification_input']=qualification_inputs['qualification-input.json'];value['candidate_patch']=qualification_inputs['candidate/candidate.patch']
        launcher='r35_campaign.py' if name.startswith('campaign-') else 'r35_lifecycle_campaign.py';value['launcher_sha256']=files[launcher]['sha256']
        if name.startswith('lifecycle-'):
            value['campaign_helpers']=dict(files['r35_campaign.py'],path=ROOT+'/tools-01/r35_campaign.py')
            value['tools_manifest']['bytes']=value['tools_manifest']['sha256']=None
        outputs[OUT/name]=canonical(value)
    check={'schema':'hepta-r35-parent-local-static-checks/v1','passed':True,
           'method':'AST and exact source identities only; campaign/preparer/helpers not imported or executed',
           'reference_r34_source_identities_verified':True,'frozen_r35_preparer_inputs_verified':True,
           'future_actual_qualification_values_null':True,'observation_nonbinder_functions_unchanged':unchanged,
           'nonbinder_prefix_suffix_bytes_equal_after_version_root_normalization':True,
           'lifecycle_materializers_and_installer_byte_equal_after_version_root_normalization':True,
           'preparer_helpers_equal_after_reader_namespace_adaptation':list(NAMES),
           'original_held_agent_byte_identical':True,'r34_reserve_scope_not_in_r35':True,
           'manifest_private_namespaces_match_r35_commands':True,
           'r35_adds_no_new_capacity_gate':True,'original_normal_measurement_gates_unchanged':True,
           'source_changed_paths':sorted(CHANGED),'source_baseline_commit':'baab4def80be7af015b2e7a594cb302f66c4130e',
           'cache_owner':'R34 closed cache only','future_counts_predicted':False,'remote_calls':0,
           'rust_build_or_tests_executed':False,'campaign_entrypoints_executed':False,'files':files}
    outputs[OUT/'LOCAL_STATIC_CHECKS.json']=canonical(check)
    outputs[OUT/'reference-r34-bundle-manifest.json']=manifest_raw
    outputs[OUT/'build_bundle.py']=Path(__file__).read_bytes()
    outputs[OUT/'README.md']=('''# R35 normal observation and lifecycle preparation

This unsealed preparation starts from the original R34 parent/control sources and the exact sealed R35 qualifier. The original normal six-host ABBA scheduler, thresholds, warmups, quiet interval, compiler monitor, boundary/recovery, process ownership and cleanup protocol remain unchanged. Fresh h35 namespaces keep this candidate separate. The original Mac held-agent implementation is byte-identical.

The qualification binder requires the actual completed first R35 preparation, native terminal, full test audit, formatted 220-input map, retained executables and closed R34 cache-owner originals. R24 remains the only source baseline; only the three frozen R35 files may differ. Actual qualification job/results/counts/binary pins remain null in these examples. The original eight-stage qualification and exact Rust CI must close before measurement.

R35 changes JSON allocation placement and command ownership. It does not contain R34's cancellation reserve and creates no extra reserve-capacity gate. The original normal observation, boundary/recovery and lifecycle gates remain required. R34's rejected observation and unexecuted lifecycle are preserved only as cache-owner history. No acceptance, throughput or lifecycle result is established by creating these files.

The installer still derives two lifecycle-script root replacements and their manifest from the original R29 tools. Future archive pins must be bound to the actual R35 installation receipt; hashes for already materialized R34 scripts must not be inherited.
''').encode()
    for path,raw in outputs.items():create(path,raw)
    print(json.dumps({'out':str(OUT),'files':len(outputs),'manifest':ident(outputs[OUT/'generated/runner-bundle-manifest.json']),
                      'static_checks':ident(outputs[OUT/'LOCAL_STATIC_CHECKS.json']),'parent':files['r35_campaign.py'],
                      'normal_lifecycle':files['r35_lifecycle_campaign.py'],'campaigns_executed':False},sort_keys=True))

if __name__=='__main__':
    os.umask(0o077);main()
