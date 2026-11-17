"""Admit the sole native CLI forwarding repair against the actual retained original driver."""
from pathlib import Path
import ast,hashlib,json
from receipt_support import regular,require,PIN
def text_node(raw,node):
    return ''.join(raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
def check(package,original_source):
    package,original_source=Path(package),Path(original_source)
    proof=json.loads(regular(package/'CATALOG_CONFIGURATION_ADAPTER.json'))
    before=regular(original_source/'qualify_public.py');retained=regular(package/'retained/catalog-config/qualify_public.py')
    after=regular(package/'qualify_public.py')
    require(before==retained and PIN(before)==proof['driver_before'] and PIN(after)==proof['driver_after'],'exact original and new driver preimages')
    a,b=proof['substitution']['before'],proof['substitution']['after']
    source=before.decode();target=after.decode()
    require(source.count(a)==target.count(b)==1 and source.replace(a,b,1)==target and target.replace(b,a,1)==source,'sole exact native argument forwarding substitution')
    oldtree,newtree=ast.parse(source),ast.parse(target)
    oldorig=next(n for n in oldtree.body if isinstance(n,ast.ClassDef) and n.name=='Original')
    neworig=next(n for n in newtree.body if isinstance(n,ast.ClassDef) and n.name=='Original')
    require(ast.dump(oldorig,include_attributes=False)==ast.dump(neworig,include_attributes=False) and text_node(source,oldorig)==text_node(target,neworig),'complete original provider raw source and AST unchanged')
    import qualify_public
    for name in qualify_public.DRIVER_FILES:
        if name=='qualify_public.py':continue
        require(regular(original_source/name)==regular(package/name),'original input/recording implementation unchanged: '+name)
    return {'status':'EXACT_NATIVE_CONFIG_ARGV_ADAPTER_PASS','driver_before':PIN(before),'driver_after':PIN(after),'original_provider_full_bytes_and_ast_equal':True,'all_other_driver_files_equal':True,'original_semantics_replayed':False,'native_hia_sources_changed':False}
