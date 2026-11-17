"""Bind new inputs to the unchanged original binary and the sole native CLI adapter."""
from pathlib import Path
import ast,json
from receipt_support import regular,PIN,require
def node_text(raw,node):return ''.join(raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
def check(capture,package):
    capture,package=Path(capture),Path(package);prior=capture/'retained/prior'
    proof=json.loads(regular(package/'CATALOG_CONFIGURATION_ADAPTER.json'))
    before=regular(prior/'source/qualify_public.py');after=regular(package/'qualify_public.py')
    require(before==regular(package/'retained/catalog-config/qualify_public.py') and PIN(before)==proof['driver_before'] and PIN(after)==proof['driver_after'],'exact reused original driver and new native adapter')
    a,b=proof['substitution']['before'],proof['substitution']['after'];old,new=before.decode(),after.decode()
    require(old.count(a)==new.count(b)==1 and old.replace(a,b,1)==new,'only native CLI forwarding changes')
    ot,nt=ast.parse(old),ast.parse(new)
    oc=next(n for n in ot.body if isinstance(n,ast.ClassDef) and n.name=='Original');nc=next(n for n in nt.body if isinstance(n,ast.ClassDef) and n.name=='Original')
    require(ast.dump(oc,include_attributes=False)==ast.dump(nc,include_attributes=False) and node_text(old,oc)==node_text(new,nc),'unchanged original recording class')
    before_cases=regular(prior/'source/public_cases.py');after_cases=regular(package/'public_cases.py');change=json.loads(regular(package/'INPUT_CHANGE.json'))
    require(before_cases==regular(package/'retained/catalog-config/public_cases.py'),'exact old catalog input preimage')
    old,new=before_cases.decode(),after_cases.decode();a,b=change['before'],change['after']
    require(old.count(a)==new.count(b)==1 and old.replace(a,b,1)==new,'only frozen new valid config input definition')
    import qualify_public
    for name in qualify_public.DRIVER_FILES:
        if name not in ('qualify_public.py','public_cases.py'):require(regular(prior/'source'/name)==regular(package/name),'unchanged recording/input implementation: '+name)
    references={}
    for name in ('main.rs','original_config.rs'):
        actual=prior/'retained/original/ci-package/reference/project/src'/name
        require(regular(actual)==regular(package/'reference'/name),'exact original compiled reference source')
        references[name]=PIN(regular(actual))
    return {'status':'EXACT_NEW_VALID_CATALOG_INPUT_DOMAIN_PASS','new_input_definition':PIN(regular(package/'INPUTS.json')),'original_references':references,'original_recording_class_equal':True,'new_valid_configuration_domain':True,'old_835_original_replayed':False,'binary_recompiled':False,'reference_cli_startup_effects_compared':False}
