"""Fresh five-image worker, two reference images, actual assembler and HIA pack."""
from __future__ import annotations
import argparse,json,os,shutil,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from worker_common import BASE,read,put,document,sha,source_evidence,require
from worker_compiler_capture import compiler_custody
from author_worker_bridge import ROLES,ASSEMBLY,author,pack

EXTRA={'old-core':'native/bellman_core.hepta','commitment':'native/bellman_commitment.hepta'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-root','hepta','capture']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-pins-sha256',required=True);p.add_argument('--bootstrap-cache',type=Path)
    a=p.parse_args();root=a.source_root.resolve();hepta=a.hepta.resolve();capture=a.capture.resolve()
    source_evidence(root,a.source_pins_sha256);capture.mkdir(mode=0o700)
    sys.path.insert(0,str(root/'scripts'))
    from hia_native_build import NativeBuild
    build=capture/'build'
    if a.bootstrap_cache is not None:shutil.copytree(a.bootstrap_cache,build/'bootstrap')
    builder=NativeBuild(hepta,build);modules={}
    for role,(name,source,source_sha,image_sha) in ROLES.items():
        manifest=builder.compile(name,root/source,standalone=None,buffer_profile='serde-json.v1')
        meta=document(manifest);require(meta['source_sha256']==source_sha and meta['image_sha256']==image_sha,'runtime image changed')
        modules[name]={'source':source,'manifest':manifest.relative_to(capture).as_posix()}
    for name,source in EXTRA.items():
        manifest=builder.compile(name,root/source,standalone=None,buffer_profile='serde-json.v1')
        modules[name]={'source':source,'manifest':manifest.relative_to(capture).as_posix()}
    # Reauthor only in an owned build workspace. Source-admitted files never
    # change when a different actual assembler path/version is recorded.
    private=capture/'mechanical-source';private.mkdir()
    names=set(ASSEMBLY)|{v[1] for v in ROLES.values()}|{'tests/hia_native/blocking_worker_ci/capture_writer_trace.py'}
    for name in names:put(private/name,read(root/name))
    bridge=capture/'bridge';author(private,hepta,build,bridge)
    expected=document(root/'native/bellman_worker_component.json');actual=document(bridge/'component.json')
    for key in ['prefix_hex','prefix_bytes','prefix_sha256','gaps','executable_bytes','executable_sha256','exports','sources','packer','source_author_sha256']:
        require(actual[key]==expected[key],'mechanical reconstruction changed: '+key)
    for role in ROLES:
        for key in ['source','source_sha256','image_sha256','image_bytes','offset']:
            require(actual['members'][role][key]==expected['members'][role][key],'runtime member layout changed')
    for name in ['native/bellman_worker_packer.hepta','native/bellman_worker_packer.author.txt']:
        require(read(private/name)==read(root/name),'actual reauthored packer changed')
    pack(private,hepta,build,bridge)
    label='worker-packer-bridge';modules[label]={'source':'native/bellman_worker_packer.hepta','manifest':f'build/modules/{label}/manifest.json'}
    compiler_custody(hepta,builder.identity,capture)
    source_evidence(root,a.source_pins_sha256)
    result={'schema':'hepta.runtime.bellman-worker-native-build.v1','status':'FRESH_HIA_AND_ACTUAL_PACK_PASS',
            'pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgid(0),'modules':modules,
            'compiler_source_identity':builder.identity,'fresh_bootstrap':a.bootstrap_cache is None,
            'reused_verified_bootstrap':a.bootstrap_cache is not None,'matching_source_cold_qualified':False,
            'component_sha256':sha(read(bridge/'component.json')),'executable_sha256':actual['executable_sha256'],
            'source_pins_sha256':a.source_pins_sha256,'public_handler_qualified':False}
    put(capture/'native-build.json',result);print(json.dumps({k:v for k,v in result.items() if k!='compiler_source_identity'},sort_keys=True))

if __name__=='__main__':main()
