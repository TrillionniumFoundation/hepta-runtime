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
    require(len(expected)==428 and produced==expected,'complete source reproduction differs')
    require((capture/'AUTHOR.json').read_bytes()==(package/'source_origin/AUTHOR.json').read_bytes(),
        'complete source author proof differs')
    require(set(inventory(capture))=={'source/'+p for p in expected}|{'AUTHOR.json'},
        'source reproduction inventory differs')
    return {'status':'EXTRACT_SOURCE_REPRODUCTION_PASS','source_files':428,
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
    print(json.dumps(verify(package,out),sort_keys=True))
if __name__=='__main__':main()
