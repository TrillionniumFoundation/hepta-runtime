"""Fresh exact-B3 compilation of the fourteen owners and actual HIA packer."""
from pathlib import Path
import argparse
import shutil
import struct
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from common import COMPILER, encoded, loads, pin, read, require, sha, source
from process import Recorder
from hia_native_build import NativeBuild
from hia_native_loader import NativeModule


def build(hepta,output,cache=None):
    frozen=source(); members=loads(read(ROOT/'MEMBERS.json'))
    output.mkdir(parents=True,exist_ok=False)
    if cache is not None:
        # Local use is permitted only with complete, reverified copied B3 custody.
        for name in ('B1','B2','B3'):
            raw=read(cache/'bootstrap'/(name+'.image.bin'))
            require(len(raw)==673413 and sha(raw)==COMPILER,'copied exact compiler generation')
        shutil.copytree(cache/'bootstrap',output/'bootstrap')
    builder=NativeBuild(hepta,output)
    require(sha(read(builder.bootstrap()))==COMPILER,'exact B3 compiler')
    rows=[]; images=[]
    for row in members['members']:
        require(row['slot']==len(rows),'fourteen ordered member slots')
        path=ROOT/row['source'];require(sha(read(path))==row['source_sha256'],'frozen member source')
        manifest=builder.compile(row['name'],path,standalone=None,buffer_profile='history.v1')
        info=loads(read(manifest));raw=read(manifest.parent/info['image'])
        require(pin(raw)==dict(bytes=row['image_bytes'],sha256=row['image_sha256']),'exact member image')
        rows.append(dict(row,manifest=str(manifest.relative_to(output)),manifest_pin=pin(read(manifest))))
        images.append(raw)
    require(len(images)==14,'complete member graph')
    module=builder.compile('extract-fixture-packer',ROOT/'native/extract_fixture_packer.hepta',
                           standalone=None,buffer_profile='history.v1')
    prefix=read(ROOT/'native/fixture-prefix.bin')
    require(pin(prefix)==dict(bytes=members['prefix_bytes'],sha256=members['prefix_sha256']),'fixed ELF prefix')
    expected=bytearray(prefix);size=len(prefix)+sum(map(len,images))
    struct.pack_into('<2Q',expected,96,size,size)
    struct.pack_into('<14Q',expected,members['table_offset'],*(len(x) for x in images))
    expected=bytes(expected)+b''.join(images)
    require(pin(expected)==members['expected_executable'],'full expected HIA executable graph')
    frame=b'HEXTPX01'+struct.pack('<14Q',*(len(x) for x in images))+b''.join(images)
    with NativeModule(module,manifest_sha256=sha(read(module))) as native:
        code,out,work=native.invoke_raw(frame,output_capacity=size+4096,workspace_capacity=4096,
                                       output_fill=0xb3,workspace_fill=0xc7)
    require(code==size and out==expected+b'\xb3'*4096 and work==b'\xc7'*4096,'complete actual HIA packing')
    for name,raw in [('pack.input.bin',frame),('pack.output.bin',out),('pack.workspace.bin',work)]:
        (output/name).write_bytes(raw)
    elf=output/'extract-lines.elf';elf.write_bytes(expected);elf.chmod(0o500)
    for name,digest in builder.identity['files'].items():
        raw=read(hepta/name);require(sha(raw)==digest,'compiler source retained in full')
        dest=output/'compiler-source'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
    require(len(builder.identity['files'])==1080,'complete compiler closure')
    # The exported mechanical boundary must be reproduced from its frozen source.
    rec=Recorder(ROOT,output/'assembly-processes')
    for name,args in [('assemble',['as','--64','-o',output/'export.o',ROOT/'native/local_extract_lines_callable.S']),
        ('link',['ld','-nostdlib','-Ttext=0','-e','local_extract_lines_run','-o',output/'export.elf',output/'export.o']),
        ('binary',['objcopy','-O','binary','--only-section=.text',output/'export.elf',output/'export.bin']),
        ('relocations',['readelf','-r',output/'export.elf']),('symbols',['nm','-n',output/'export.elf'])]:
        rec.run(name,args,timeout=60)
    require(b'There are no relocations' in read(output/'assembly-processes/relocations.stdout'),'fixed adapter has no relocations')
    symbols={line.split()[-1]:int(line.split()[0],16) for line in read(output/'assembly-processes/symbols.stdout').decode().splitlines() if len(line.split())==3}
    exports={name:symbols['local_extract_lines_'+name] for name in ('run','resume','cancel_wait','release')}
    require(exports==members['exports'] and pin(read(output/'export.bin'))==members['export_code'],'exact exported adapter bytes and entry offsets')
    require(source()==frozen,'source remains frozen')
    result=dict(schema='hepta.extract-lines.native-build.v1',status='PASS',source_manifest_sha256=frozen,
        compiler_sha256=COMPILER,copied_bootstrap=cache is not None,members=rows,
        packer_manifest=str(module.relative_to(output)),packer_manifest_pin=pin(read(module)),
        executable=dict(path=elf.name,**pin(expected)),exports=exports,export_code=pin(read(output/'export.bin')),
        fresh_module_compiles=15,actual_packer_calls=1,public_handler_qualified=False)
    (output/'BUILD.json').write_bytes(encoded(result));print(encoded(result).decode(),end='')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--hepta',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--cache',type=Path);a=p.parse_args()
    build(a.hepta.resolve(strict=True),a.output.absolute(),None if a.cache is None else a.cache.resolve(strict=True))
