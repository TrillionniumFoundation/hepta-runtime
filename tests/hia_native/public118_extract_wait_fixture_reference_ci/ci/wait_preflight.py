"""Freeze and verify both real wait-fixture sources; assemble but execute no image."""
from pathlib import Path
import argparse,hashlib,importlib,json,stat,sys,traceback,types
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'reference')]
from common import pin,put,require
from source_check import source
from receipt_support import process
import wait_native_fixture
def main():
    p=argparse.ArgumentParser()
    for n in ('package','runtime','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);a=p.parse_args()
    package=a.package.resolve(strict=True);root=a.runtime.resolve(strict=True);out=a.output.absolute()
    require(not out.exists(),'fresh fixture source preflight exists');out.mkdir()
    put(out/'START.json',{'package':str(package),'runtime':str(root),'native_or_rust_semantic_executions':0})
    try:
        admitted=source(package,a.manifest_sha256,True)
        expected=json.loads((HERE/'RUNTIME_SOURCE_ROWS.json').read_bytes())
        require(len(expected)==464,'actual public WAIT complete source closure')
        for row in expected:
            path=root/row['path'];raw=path.read_bytes()
            require(path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode),'runtime source alias')
            require(pin(path)=={k:row[k] for k in ('bytes','sha256')}
                and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob']
                and format(stat.S_IFREG|stat.S_IMODE(path.stat().st_mode),'o')==row['mode'],
                'runtime source differs: '+row['path'])
        ref=package/'reference';path=ref/'authoring/author_public_reference.py'
        author=types.ModuleType('actual_wait_reference_source');author.__file__=str(path)
        exec(compile(path.read_bytes(),str(path),'exec',dont_inherit=True),author.__dict__)
        generated,original=author.compose(ref/'baseline',ref/'core')
        require(set(generated)=={p.relative_to(ref/'project').as_posix() for p in (ref/'project').rglob('*') if p.is_file()},
            'complete generated reference source inventory')
        for name,raw in generated.items():require((ref/'project'/name).read_bytes()==raw,'reference source reproduction: '+name)
        require(len(generated)==44 and original['wait_fixture']['public_wait_qualified'] is False,
            'fixed wait source scope')
        sys.path.insert(0,str(root/'scripts'))
        builder=importlib.import_module('public_nine_build')
        require(Path(builder.__file__).resolve()==root/'scripts/public_nine_build.py','foreign graph builder')
        before,after,adaptation=wait_native_fixture.source(root,builder)
        (out/'base.S').write_bytes(before);(out/'fixture.S').write_bytes(after)
        put(out/'ADAPTATION.json',adaptation)
        process(out/'processes','assemble',['as','--64','-o',out/'fixture.o',out/'fixture.S'],
            cwd=out,timeout=60)
        _,symbols,stderr=process(out/'processes','undefined-symbols',['nm','-u',out/'fixture.o'],
            cwd=out,timeout=60)
        require(symbols==stderr==b'','fixture unresolved symbol')
        _,relocations,stderr=process(out/'processes','relocations',['readelf','-r',out/'fixture.o'],
            cwd=out,timeout=60)
        require(relocations==b'\nThere are no relocations in this file.\n' and stderr==b'','fixture relocation')
        report={'status':'ACTUAL_WAIT_FIXTURE_SOURCE_AND_ASSEMBLY_PASS','source_admission':admitted,
            'native_source_files':464,'reference_files':44,'native_boundary_adaptation':adaptation,
            'actual_assembler_object':pin(out/'fixture.o'),'unchanged_original_target_items':len(original['preserved_original_items']),
            'unchanged_extract_target_spans':len(original['extract_exact_spans']),
            'native_or_rust_semantic_executions':0,'production_files_changed':False,'public_wait_qualified':False}
        put(out/'PASS.json',report);print(json.dumps(report,sort_keys=True))
    except BaseException as e:
        put(out/'FAILURE.json',{'status':'FAIL','error':repr(e),'traceback':traceback.format_exc(),
            'native_or_rust_semantic_executions':0});raise
if __name__=='__main__':main()
