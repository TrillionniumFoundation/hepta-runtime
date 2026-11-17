"""Load both exact readers/builders before the read-only guard is installed."""
from pathlib import Path
import ast,importlib.util,sys
from async_build_common import require
LOADED={}
def load(graph):
    graph=Path(graph).resolve(strict=True);key=str(graph)
    if key in LOADED:return LOADED[key]
    path=graph/"scripts/public_nine_build.py"
    spec=importlib.util.spec_from_file_location("publication_current_builder_"+str(len(LOADED)),path)
    builder=importlib.util.module_from_spec(spec)
    name="runtime_mcp_publication_async";missing=object();previous=sys.modules.pop(name,missing)
    try:
        spec.loader.exec_module(builder)
        helper=sys.modules[name]
        require(Path(helper.__file__).resolve()==graph/"scripts/runtime_mcp_publication_async.py",
            "exact per-graph publication helper import")
        require(builder.combine_async is helper.combine_async,"builder retains actual helper callable")
    finally:
        if previous is missing:sys.modules.pop(name,None)
        else:sys.modules[name]=previous
    require(Path(builder.__file__).resolve()==path,"actual current builder source")
    tree=ast.parse(path.read_bytes())
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="build_runtime_mcp")
    value=next(n.value for n in fn.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="result" for t in n.targets))
    literal,keys={},set(builder.FALSE_FLAGS)
    for k,v in zip(value.keys,value.values,strict=True):
        if k is None:continue
        name=ast.literal_eval(k);keys.add(name)
        try:literal[name]=ast.literal_eval(v)
        except (ValueError,TypeError):pass
    for flag in builder.FALSE_FLAGS:literal[flag]=False
    LOADED[key]=(builder,literal,keys)
    return LOADED[key]
