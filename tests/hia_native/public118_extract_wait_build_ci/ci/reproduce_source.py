"""Reproduce only source authoring, then compare every original byte and mode.

verify() is a read-only reader. Only the explicit CLI performs Python AST source
authoring; no HIA image, assembler, compiler, Rust, or fixture is executed here.
"""
from pathlib import Path
import argparse,hashlib,json,stat,sys,types
sys.dont_write_bytecode=True
def require(ok,text):
    if not ok:raise ValueError(text)
def pin(path):
    path=Path(path);raw=path.read_bytes()
    require(stat.S_ISREG(path.lstat().st_mode),'nonregular source: '+str(path))
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
        'mode':'100755' if path.stat().st_mode&0o111 else '100644'}
def inventory(root):
    root=Path(root);result={}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(),'source symlink')
        if path.is_dir():continue
        result[path.relative_to(root).as_posix()]=pin(path)
    return result
def verify(package,capture):
    package,capture=Path(package),Path(capture)
    expected={r['path']:{k:r[k] for k in ('bytes','sha256','git_blob','mode')}
        for r in json.loads((package/'INPUTS.json').read_bytes())['installed_graph_rows']}
    produced=inventory(capture/'source')
    require(len(expected)==464 and produced==expected,'complete source reproduction differs')
    baseline_rows=json.loads((package/'graph/source/authoring/public_extract_wait_v1/BASELINE_SOURCE_ROWS.json').read_bytes())
    baseline={r['path']:{k:r[k] for k in ('bytes','sha256','git_blob','mode')} for r in baseline_rows}
    require(len(baseline)==452 and inventory(capture/'baseline-source')==baseline,
        'complete retained pre-WAIT source differs')
    changes={n:{'before':{k:baseline[n][k] for k in ('bytes','sha256')} if n in baseline else None,
                   'after':{k:r[k] for k in ('bytes','sha256')}}
             for n,r in expected.items() if n not in baseline or r!=baseline[n]}
    proof={'schema':'hepta.runtime.public118-extract-wait-source-result.v1',
      'status':'PURE_SOURCE_AUTHOR_PASS','baseline_source':'58e1e21f4e3e8af93f0f49e15e652d71fa1b6b71',
      'source_binding_sha256':'25b60896263c8eacc0933e0df3f8ed38c00e4991795ce4bbf1b2022e7170269c',
      'source_files':464,'runtime_hia_images':118,'physical_images':111,'descriptor_slots':64,
      'installed_handlers':10,'changed_files':changes,'source_rows':json.loads((package/'INPUTS.json').read_bytes())['installed_graph_rows'],
      'semantic_executions':0,'public_wait_qualified':False,'full_async_qualified':False,'whole_runtime_replaced':False}
    require(json.loads((capture/'WAIT_AUTHOR.json').read_bytes())==proof,
        'complete actual WAIT author source result differs')
    require((capture/'AUTHOR.json').read_bytes()==(package/'source_origin/AUTHOR.json').read_bytes(),
        'complete source author proof differs')
    require((capture/'RETAINED_REPAIR_AUTHOR.json').read_bytes()==(package/'source_origin/RETAINED_REPAIR_AUTHOR.json').read_bytes(),'complete prior source author proof differs')
    require((capture/'RETAINED_OWNER_CLEAR_AUTHOR.json').read_bytes()==(package/'source_origin/RETAINED_OWNER_CLEAR_AUTHOR.json').read_bytes(),'complete retained caller-clear source proof differs')
    require((capture/'RETAINED_CUSTOM_AUTHOR.json').read_bytes()==(package/'source_origin/RETAINED_CUSTOM_AUTHOR.json').read_bytes(),'complete retained typed-custom source proof differs')
    require(set(inventory(capture))=={'source/'+p for p in expected}|{'baseline-source/'+p for p in baseline}|{'WAIT_AUTHOR.json','AUTHOR.json','RETAINED_REPAIR_AUTHOR.json','RETAINED_OWNER_CLEAR_AUTHOR.json','RETAINED_CUSTOM_AUTHOR.json'},
        'source reproduction inventory differs')
    return {'status':'EXTRACT_SOURCE_REPRODUCTION_PASS','source_files':464,
        'source_binding':pin(capture/'source/native/runtime_mcp_sources.json'),
        'author':pin(capture/'AUTHOR.json'),'all_bytes_and_modes_equal':True,
        'native_or_rust_executed':False}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','hepta','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();package=a.package.resolve(strict=True);out=a.output.absolute()
    require(not out.exists(),'source author output already exists')
    author=package/'graph/source/authoring/public_extract_repair/author.py'
    module=types.ModuleType('retained_extract_source_author');module.__file__=str(author)
    exec(compile(author.read_bytes(),str(author),'exec',dont_inherit=True),module.__dict__)
    module.generate(package/'repair_inputs/base',package/'repair_inputs/configured',a.hepta.resolve(strict=True),out)
    prior=(out/'AUTHOR.json').read_bytes();require(prior==(package/'source_origin/RETAINED_REPAIR_AUTHOR.json').read_bytes(),'retained exact source reproduction')
    (out/'RETAINED_REPAIR_AUTHOR.json').write_bytes(prior)
    clear=package/'graph/source/authoring/public_owner_clear/author.py'
    overlay=types.ModuleType('retained_caller_clear_source_author');overlay.__file__=str(clear)
    exec(compile(clear.read_bytes(),str(clear),'exec',dont_inherit=True),overlay.__dict__)
    proof=overlay.apply(out/'source',a.hepta.resolve(strict=True))
    prior=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
    require(prior==(package/'source_origin/RETAINED_OWNER_CLEAR_AUTHOR.json').read_bytes(),'exact retained caller-clear source reproduction')
    (out/'RETAINED_OWNER_CLEAR_AUTHOR.json').write_bytes(prior)
    custom=package/'graph/source/authoring/public_custom_request/author.py'
    current=types.ModuleType('typed_custom_request_source_author');current.__file__=str(custom)
    exec(compile(custom.read_bytes(),str(custom),'exec',dont_inherit=True),current.__dict__)
    proof=current.apply(out/'source',a.hepta.resolve(strict=True))
    prior=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
    require(prior==(package/'source_origin/RETAINED_CUSTOM_AUTHOR.json').read_bytes(),'exact retained typed-custom source reproduction')
    (out/'RETAINED_CUSTOM_AUTHOR.json').write_bytes(prior)
    mixed=package/'graph/source/authoring/public_mixed_opener/author.py'
    current=types.ModuleType('mixed_opener_catalog_source_author');current.__file__=str(mixed)
    exec(compile(mixed.read_bytes(),str(mixed),'exec',dont_inherit=True),current.__dict__)
    proof=current.apply(out/'source',a.hepta.resolve(strict=True),package/'source_origin/locked_sdk_server.rs')
    (out/'AUTHOR.json').write_bytes((json.dumps(proof,sort_keys=True,indent=2)+'\n').encode())
    (out/'source').rename(out/'baseline-source')
    wait=package/'graph/source/authoring/public_extract_wait_v1/author.py'
    current=types.ModuleType('actual_lock_wait_source_author');current.__file__=str(wait)
    exec(compile(wait.read_bytes(),str(wait),'exec',dont_inherit=True),current.__dict__)
    proof=current.apply(out/'baseline-source',a.hepta.resolve(strict=True),out/'source')
    (out/'WAIT_AUTHOR.json').write_bytes((json.dumps(proof,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps(verify(package,out),sort_keys=True))
if __name__=='__main__':main()
