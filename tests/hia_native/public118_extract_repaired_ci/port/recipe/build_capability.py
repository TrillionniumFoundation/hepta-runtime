"""One portable entry for the fixed, shared Bellman capability build."""
import argparse,json,os,pathlib,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from qualify_port import source_evidence,encoded
from port_build_evidence import verify_build

def build_bellman_port(hepta,build_root,worker_build,*,package,package_sha256):
    package=pathlib.Path(package).resolve();hepta=pathlib.Path(hepta).resolve()
    build_root=pathlib.Path(build_root).resolve();worker_build=pathlib.Path(worker_build).resolve()
    sources=source_evidence(package,package_sha256);build_root.mkdir()
    sys.path.insert(0,str(package/'worker-source/tests/hia_native/blocking_worker_ci'))
    from capture_writer_trace import run
    py=[sys.executable,'-I','-S','-B']
    run(build_root,'portable-build',py+[str(package/'recipe/build_port.py'),'--package',str(package),'--hepta',str(hepta),'--worker-build',str(worker_build),'--output',str(build_root/'build-v3')],dict(os.environ),limit=180)
    run(build_root,'portable-pack',py+[str(package/'recipe/pack_port.py'),'--package',str(package),'--hepta',str(hepta),'--build',str(build_root/'build-v3')],dict(os.environ),limit=180)
    evidence=verify_build(build_root/'build-v3',package/'source',worker_build,package/'worker-source')
    result={'schema':'hepta.runtime.bellman-public-port-build.v1','sources':sources,'build':evidence,'component':'build-v3/component.json','packer_receipt':'build-v3/pack.receipt.json','executable':'build-v3/bellman-port-packed.elf','public_handler_qualified':False}
    manifest=build_root/'port-build.json';manifest.write_bytes(encoded(result));return manifest

def main():
    p=argparse.ArgumentParser()
    for name in ('package','hepta','worker-build','output'):p.add_argument('--'+name,type=pathlib.Path,required=True)
    p.add_argument('--package-sha256',required=True);a=p.parse_args()
    manifest=build_bellman_port(a.hepta,a.output,a.worker_build,package=a.package,package_sha256=a.package_sha256)
    print(json.dumps({'manifest':str(manifest),'public_handler_qualified':False},sort_keys=True))
if __name__=='__main__':main()
