"""Fixed native I/O helpers, with the complete retained read dependency build."""
from pathlib import Path
import json
import struct
import subprocess
import sys
import time
from public_read_build import source_paths as read_paths, constants
from public_read_build import build_images as build_read_images
from hia_native_public_read_dependencies import pin, require, encoded

PUBLIC_BASE_BINDING={'bytes':189491,'sha256':'4b77517b7c1d6eba96ede8fbfaaed51446ca1908c96ff6c63ce49e328e20c514'}


def verify_base(root):
    """Resolve every byte of the unchanged previous 856-file public closure."""
    folder=root/'authoring/public_binary_write/public_base'
    document=root/'authoring/public_binary_write/PUBLIC_BASE.json'
    data=json.loads(document.read_bytes())
    binding=folder/'native/runtime_mcp_sources.json'
    require(pin(binding)==PUBLIC_BASE_BINDING,'whole previous public binding differs')
    old=json.loads(binding.read_bytes())
    require(len(old['sources'])==856 and data['binding']==PUBLIC_BASE_BINDING,
            'whole previous public source extent differs')
    retained=set(data['retained_paths'])
    require(retained<=old['sources'].keys(),'retained override was absent from the previous graph')
    selected={}
    for name,expected in old['sources'].items():
        relative=Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts,'previous public source path escaped')
        path=(folder if name in retained else root)/name
        require(not path.is_symlink() and path.is_file() and pin(path)==expected,
                'complete previous public source inverse differs: '+name)
        selected[name]=path
    return selected,binding


def source_paths(root):
    paths=set(read_paths(root))
    paths.update(('scripts/public_io_build.py','scripts/hia_native_public_binary_write.py',
                  'asm/ssh_direct/qualified-relocatable.ld','native/public_ssh_object_layout.json',
                  'native/public_file_info_alignment.json','native/public_multi_read_alignment.json',
                  'scripts/jobs_audit_author_canonical.py','asm/jobs_audit_canonical.json',
                  'native/public_binary_write_component.json','asm/public_binary_write_stdio.S',
                  'runtime_support/binary_write/ORIGIN.json'))
    for prefix in ('runtime_support/binary_write/source','authoring/public_binary_write',
                   'authoring/jobs_audit_event'):
        for path in (root/prefix).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                paths.add(path.relative_to(root).as_posix())
    for name in ('public_io_frontend','public_io_gateway','public_io_wire',
                 'public_binary_write_gateway','public_binary_parent_owner',
                 'public_binary_write_body','public_binary_base64_decode',
                 'jobs_audit_event','jobs_audit_append','jobs_audit_namespace'):
        for suffix in ('.hepta','_composition.json'):
            paths.add('native/'+name+suffix)
    return sorted(paths)


def build_images(root,build,folder):
    images,read=build_read_images(root,build,folder)
    output=folder/'public-binary-write'
    command=[sys.executable,'-I','-S','-B',str(root/'scripts/hia_native_public_binary_write.py'),
             '--source',str(root),'--hepta',str(build.hepta),
             '--bootstrap',str(build.root/'bootstrap'),'--output',str(output)]
    started=time.monotonic()
    with (folder/'binary-write-build.stdout').open('xb') as stdout,(folder/'binary-write-build.stderr').open('xb') as stderr:
        process=subprocess.run(command,cwd=root,stdout=stdout,stderr=stderr,check=False)
    receipt={'command':command,'returncode':process.returncode,'seconds':time.monotonic()-started,
             'stdout':pin(folder/'binary-write-build.stdout'),'stderr':pin(folder/'binary-write-build.stderr')}
    (folder/'binary-write-build.process.json').write_bytes(encoded(receipt))
    require(process.returncode==0 and receipt['stderr']['bytes']==0,'actual binary-write dependency build failed')
    writer=json.loads((output/'BUILD.json').read_bytes())
    component=json.loads((root/'native/public_binary_write_component.json').read_bytes())
    elf=output/'public-binary-write.elf'
    require(writer['status']=='PASS' and len(writer['runtime_images'])==component['runtime_hia_images']==10,
            'fixed binary-write member count differs')
    require(pin(elf)==writer['executable']==component['executable'],'fixed binary-write executable differs')
    writer['process']=receipt
    original=images['read_helpers'].read_bytes()
    require(original[:8]==b'HRRMIMG1' and original[32:64]==bytes(32),'retained read bundle shape differs')
    sizes=struct.unpack_from('<3Q',original,8)
    require(len(original)==64+sum(sizes),'retained complete read helper lengths differ')
    data=elf.read_bytes();bundle=folder/'public-io-helper-images.bin'
    bundle.write_bytes(b'HRRMIMG1'+struct.pack('<7Q',*sizes,len(data),0,0,0)+original[64:]+data)
    images['read_helpers']=bundle
    # Reproduce the full canonical transport transform at the public build,
    # including the original thirteen closed effects and both private fds.
    canonical=folder/'jobs-audit-canonical-authored'
    process=subprocess.run([sys.executable,'-I','-S','-B',str(root/'scripts/jobs_audit_author_canonical.py'),
                            '--source',str(root),'--output',str(canonical)],
                           cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    require(process.returncode==0 and not process.stderr,'audit canonical author reproduction failed')
    for name in ('jobs_audit_canonical.S','jobs_audit_canonical.json'):
        require((root/'asm'/name).read_bytes()==(canonical/name).read_bytes(),
                'complete audit canonical transport differs: '+name)
    report={'schema':'hepta.runtime.public-io.packed-dependencies.v1','read':read,'write':writer,
            'helper_bundle':pin(bundle),'helper_kinds_built':[1,2,3,4],
            'runtime_hia_image_instances':read['runtime_hia_image_instances']+10,
            'canonical_author_reproduced':True,'public_routes_qualified':False}
    (folder/'PUBLIC_IO_BUILD.json').write_bytes(encoded(report))
    return images,report
