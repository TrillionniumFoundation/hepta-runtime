"""Fresh fixed-point HIA build of the audit record policy and its qualified JSON child."""
from pathlib import Path
import argparse
import stat
import sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT),str(ROOT/'scripts')]
from common import COMPILER, encoded, loads, pin, read, require, source
from hia_native_build import NativeBuild

def run(hepta,output):
    identity=source()
    builder=NativeBuild(hepta,output)
    expected=loads(read(ROOT/'COMPILER_IDENTITY.json'))
    require(builder.identity==expected,'complete fixed compiler source closure')
    require(pin(read(builder.bootstrap()))==dict(bytes=673413,sha256=COMPILER),'fresh exact B1/B2/B3')
    modules={}
    for name,path in (('audit-record-io','native/audit_record_io.hepta'),
                      ('audit-json','imports/audit_json.hepta')):
        manifest=builder.compile(name,ROOT/path,standalone=None)
        modules[name]=dict(source_path=path,source=pin(read(ROOT/path)),
            manifest=dict(path=str(manifest.relative_to(output)),**pin(read(manifest))),
            image=pin(read(manifest.parent/'module.image.bin')))
    for name,digest in expected['files'].items():
        raw=read(hepta/name)
        require(pin(raw)['sha256']==digest,'complete retained compiler source')
        dest=output/'compiler-source'/name;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(raw);dest.chmod(stat.S_IMODE((hepta/name).stat().st_mode))
    require(source()==identity,'source unchanged across actual build')
    result=dict(schema='hepta.audit-record-io.build.v1',source_manifest_sha256=identity,
        compiler=expected,compiler_image=dict(bytes=673413,sha256=COMPILER),modules=modules,
        fresh_hia_compile=True,public_handler_qualified=False,whole_runtime_replaced=False)
    (output/'BUILD.json').write_bytes(encoded(result))
    print(encoded(result).decode(),end='')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hepta',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.output.absolute())
