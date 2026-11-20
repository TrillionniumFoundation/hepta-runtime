#!/usr/bin/env python3
"""Compile the unchanged Map/typed/planner and new adapter with exact retained B3."""
import argparse
import json
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'dependency/scripts'))
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild
from common import B3,source_evidence,pin,save,require


def inventory(root):
    rows={}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(),'bootstrap symlink')
        if path.is_file():rows[path.relative_to(root).as_posix()]=dict(**pin(path),mode=stat.S_IMODE(path.stat().st_mode))
    return rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('hepta','retained-bootstrap','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();out=a.output.absolute()
    require(not out.exists(),'fresh build output')
    identity=source_evidence()
    began=time.monotonic_ns()
    builder=NativeBuild(a.hepta,out/'build')
    require(builder.identity==json.loads((ROOT/'COMPILER_INPUT.json').read_bytes()),'entire compiler source identity')
    retained=a.retained_bootstrap.resolve(strict=True)
    before=inventory(retained)
    shutil.copytree(retained,out/'build/bootstrap',copy_function=shutil.copy2)
    require(inventory(out/'build/bootstrap')==before,'copied complete bootstrap bytes/modes')
    require(pin(builder.bootstrap())['sha256']==B3,'actual B3 bytes')
    command=[sys.executable,'-I','-S','-B',str(ROOT/'authoring/author_adapter.py'),'--source',str(ROOT),'--hepta',str(a.hepta.resolve()),'--output',str(out/'authored')]
    with (out/'author.stdout').open('xb') as stdout,(out/'author.stderr').open('xb') as stderr:
        author=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=30,check=False)
    require(author.returncode==0 and (out/'author.stderr').stat().st_size==0,'actual HIA author succeeded')
    for name in ('binary_write_adapter.hepta','binary_write_adapter_composition.json','binary_write_adapter.pseudo'):
        require((ROOT/'native'/name).read_bytes()==(out/'authored'/name).read_bytes(),'frozen complete HIA author output')
    members={}
    for name,path in [('map','dependency/native/serde_json_span.hepta'),('typed','dependency/native/binary_write_params.hepta'),('planner','dependency/native/binary_call_plan.hepta'),('adapter','native/binary_write_adapter.hepta')]:
        manifest=builder.compile('binary-write-adapter-'+name,ROOT/path,standalone=None,buffer_profile='history.v1')
        meta=json.loads(manifest.read_bytes())
        members[name]=dict(source_path=path,source=pin(ROOT/path),manifest=manifest.relative_to(out).as_posix(),identity=pin(manifest),image=pin(manifest.parent/meta['image']))
        print(json.dumps(dict(compiled=name,image=members[name]['image']),sort_keys=True),flush=True)
    builder._recheck()
    require(before==inventory(retained)==inventory(out/'build/bootstrap'),'all original bootstrap bytes unchanged')
    for name,sha in builder.identity['files'].items():
        destination=out/'compiler-source'/name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(a.hepta/name,destination)
        require(pin(destination)['sha256']==sha,'copied compiler source bytes')
    require(source_evidence()==identity,'source stayed frozen throughout build')
    save(out/'IMAGES.json',dict(schema='hepta.runtime.binary-write-adapter.images.v1',status='FRESH_ACTUAL_B3_COMPILE_PASS',
        source=identity,compiler=builder.identity,compiler_image=pin(builder.bootstrap()),members=members,retained_bootstrap=before,
        author_command=command,author_exit_code=author.returncode,elapsed_ns=time.monotonic_ns()-began,actual_hia_compilations=4,
        new_seed_executions=0,new_bootstrap_generations=0,parent_effects_executed=0,public_binary_write_registered=False,whole_runtime_replaced=False))


if __name__=='__main__':main()
