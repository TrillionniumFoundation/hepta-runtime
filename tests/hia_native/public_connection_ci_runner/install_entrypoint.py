"""Install the default public83 entrypoint without changing any graph bytes."""
from pathlib import Path
import argparse,hashlib,json,shutil,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_source import check
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ENTRY="scripts/hia_native_runtime_mcp_build.py"
BINDING="native/runtime_mcp_sources.json"
def expected(source,runner):
    check(source)
    data=(runner/"entrypoint/hia_native_runtime_mcp_build.py").read_bytes()
    binding=json.loads((source/"source"/BINDING).read_bytes())
    assert ENTRY in binding["sources"]
    binding["sources"][ENTRY]=dict(bytes=len(data),sha256=SHA(data))
    return {ENTRY:data,BINDING:(json.dumps(binding,sort_keys=True,indent=2)+"\n").encode()}
def verify(source,runner,installed):
    replacements=expected(source,runner)
    originals={p.relative_to(source/"source").as_posix():p for p in (source/"source").rglob("*") if p.is_file()}
    actual={p.relative_to(installed).as_posix():p for p in installed.rglob("*") if p.is_file()}
    assert set(originals)==set(actual) and len(actual)==172
    for name,path in actual.items():
        assert not path.is_symlink()
        assert path.read_bytes()==replacements.get(name,originals[name].read_bytes()),name
    return dict(files=172,changed_paths=sorted(replacements),all_hia_and_assembly_bytes_unchanged=True,
        default_entrypoint_sha256=SHA(replacements[ENTRY]),source_binding_sha256=SHA(replacements[BINDING]))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);runner=Path(__file__).resolve().parent
    output=a.output.absolute();assert not output.exists()
    replacements=expected(source,runner)
    shutil.copytree(source/"source",output,copy_function=shutil.copyfile)
    for name,raw in replacements.items():(output/name).write_bytes(raw)
    print(json.dumps(dict(status="DEFAULT_PUBLIC83_ENTRY_INSTALLED",**verify(source,runner,output)),sort_keys=True))
if __name__=="__main__":main()
