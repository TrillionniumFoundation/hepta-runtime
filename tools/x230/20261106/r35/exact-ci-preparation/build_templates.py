#!/usr/bin/env python3
"""Prepare R35 exact CI templates from frozen R34 inputs; no runtime execution."""
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint

BASE = Path('/tmp/hepta-runtime-recovery-20261106')
OLD = BASE / 'r34-exact-ci-template-01'
OUT = BASE / 'r35-exact-ci-template-01'
OLD_ROOT = '/home/qian/hepta-runtime-optimization-20261106-r34'
ROOT = '/home/qian/hepta-runtime-optimization-20261106-r35'

def need(ok, why):
    if not ok:
        raise ValueError(why)

def ident(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def canonical(x):
    return (json.dumps(x,indent=2,sort_keys=True)+'\n').encode()

def create(path, raw):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())

def rename(text):
    return text.replace(OLD_ROOT, ROOT).replace('r34','r35').replace('R34','R35')

def assigned(text,name):
    nodes=[x for x in ast.parse(text).body if isinstance(x,ast.Assign)
           and len(x.targets)==1 and isinstance(x.targets[0],ast.Name) and x.targets[0].id==name]
    need(len(nodes)==1,'unique assignment: '+name)
    return nodes[0]

def literal(text,name):
    return ast.literal_eval(assigned(text,name).value)

def replace_assignment(text,name,value):
    node=assigned(text,name); lines=text.splitlines(keepends=True)
    lines[node.lineno-1:node.end_lineno]=[name+' = '+pprint.pformat(value,sort_dicts=True)+'\n']
    return ''.join(lines)

def main():
    need(not OUT.exists(),'create-only preparation directory required')
    original_manifest_raw=(OLD/'unsealed-manifest.json').read_bytes()
    manifest=json.loads(original_manifest_raw)
    checks=json.loads((OLD/'LOCAL_STATIC_CHECKS.json').read_bytes())
    need(manifest['sealed'] is False and checks['passed'] is True,'original unsealed state')
    need(manifest['files']==checks['files'],'original manifest/static identities differ')
    original={}
    for name,pin in manifest['files'].items():
        raw=(OLD/name).read_bytes()
        need(ident(raw)==pin,'original frozen file differs: '+name)
        original[name]=raw
    generated={name:(raw if name.startswith('fixed/') else rename(raw.decode()).encode())
               for name,raw in original.items()}
    template_ids={Path(name).name:ident(raw) for name,raw in generated.items() if name.startswith('templates/')}
    generated['seal_package.py']=replace_assignment(generated['seal_package.py'].decode(),
                                                   'TEMPLATE_PINS',template_ids).encode()
    for name,raw in generated.items():
        if name.endswith('.py'):
            ast.parse(raw,filename=name)
        if name.startswith('templates/'):
            need(raw==rename(original[name].decode()).encode(),'template body changed beyond version/root')
        if name.startswith('fixed/'):
            need(raw==original[name],'original CI auditor/workflow changed')
    old_seal=rename(original['seal_package.py'].decode())
    normal=replace_assignment(old_seal,'TEMPLATE_PINS',template_ids)
    need(ast.dump(ast.parse(normal),include_attributes=False)==
         ast.dump(ast.parse(generated['seal_package.py']),include_attributes=False),'sealer behavior differs')
    materializer=generated['templates/materialize_rust_ci_plan_01.py'].decode()
    launcher=generated['templates/launch_exact_rust_ci_01.py'].decode()
    runner=generated['templates/run_rust_ci_01.py'].decode()
    future=('JOB_ID','SOURCE_MAP_SHA','ISOLATED_SUMMARY_SHA','ISOLATED_AUDIT_SHA',
            'QUALIFICATION_REPORT_SHA','PREPARATION_SHA','NATIVE_TERMINAL_SHA','PARENT_SHA',
            'QUALIFICATION_BINDINGS_SHA','FROZEN_COUNTS')
    need(all(literal(materializer,name) is None for name in future),'future Q pin invented')
    need(literal(launcher,'SPEC') is None,'launcher prematurely sealed')
    example=json.loads(generated['actual-pins.example.json'])
    example['note']=example['note'].replace('The currently running qualification job does not establish success.', 'No qualification success is assumed.')
    generated['actual-pins.example.json']=canonical(example)
    need(example['qualification_job_id'] is None and all(x['local_path'] is None and x['bytes'] is None
         and x['sha256'] is None for x in example['files'].values()),'future receipt invented')
    main_node=next(x for x in ast.parse(materializer).body if isinstance(x,ast.FunctionDef) and x.name=='main')
    need(ast.unparse(main_node.body[0])=='require_frozen_qualification()','materializer guard order')
    need(runner.index('materializer.require_frozen_qualification()')<runner.index('OUT.mkdir')
         <runner.index('subprocess.Popen'),'runner guard order')
    need(launcher.index('need(type(SPEC) is dict')<launcher.index('subprocess.run'),'launcher guard order')
    constants=('STAGES','COMMANDS','INVENTORY_COMMAND','BINARY_NAMES','CI_MANIFEST_SHA',
               'NEXTEST_ROOT','NEXTEST_RECEIPT_SHA','NEXTEST_BINARY')
    oldmat=original['templates/materialize_rust_ci_plan_01.py'].decode()
    for name in constants:
        need(ast.dump(assigned(materializer,name).value,include_attributes=False)==
             ast.dump(assigned(oldmat,name).value,include_attributes=False),'CI contract differs: '+name)
    ids={name:ident(raw) for name,raw in sorted(generated.items())}
    new_manifest=json.loads(rename(original_manifest_raw.decode()))
    new_manifest['files']=ids
    report={'schema':'hepta-r35-exact-ci-unsealed-static-review/v1','passed':True,
            'reference_r34_manifest':ident(original_manifest_raw),
            'method':'byte identity, AST and fixed contract comparison only; no module import or entrypoint execution',
            'template_bodies_unchanged_except_version_root':True,
            'sealer_unchanged_except_version_root_and_template_pins':True,
            'fixed_ci_contract_constants_unchanged':list(constants),
            'auditor_and_canonical_workflow_byte_identical':True,
            'future_actual_assignments_null':list(future),'launcher_SPEC_null':True,
            'example_note_is_generic_and_infers_no_running_job':True,
            'guard_before_effects':True,'candidate_test_count_prediction':None,
            'x230_or_mac_calls':0,'ci_executed':False,'rust_compiled_or_tested':False,
            'benchmark_executed':False,'templates_imported_or_executed':False,'files':ids}
    generated['unsealed-manifest.json']=canonical(new_manifest)
    generated['LOCAL_STATIC_CHECKS.json']=canonical(report)
    generated['reference-r34-manifest.json']=original_manifest_raw
    generated['build_templates.py']=Path(__file__).read_bytes()
    generated['README.md']=('''# R35 exact Rust CI preparation

These unsealed tools preserve the R34 exact native CI commands, stage order, complete test inventory, nextest 0.9.137, auditor, and canonical workflow. Only the candidate version/root and derived template identities change. The original reference manifest is retained. No Rust command, harness, benchmark, or remote action ran to prepare these files.

All actual qualification job IDs, counts, receipt hashes, formatted compiler input hashes, and the parent binder identity remain null. The normal sealer must receive the actual successful first R35 qualification originals and the reviewed R35 parent binder; the launcher, materializer and runner fail before output creation or commands while unsealed. Qualification uses the existing `qualification-input.json` and `candidate/candidate.patch` locations. R35 is based on accepted R24, while closed R34 may supply rebuildable cache only.

This package supplies no qualification, CI, hosted Actions, performance or adoption result. R24 remains the accepted runtime.
''').encode()
    for name,raw in generated.items():
        create(OUT/name,raw)
    print(json.dumps({'out':str(OUT),'files':len(generated),'manifest':ident(generated['unsealed-manifest.json']),
                      'static_checks':ident(generated['LOCAL_STATIC_CHECKS.json']),
                      'remote_calls':0,'ci_executed':False},sort_keys=True))

if __name__=='__main__':
    os.umask(0o077)
    main()
