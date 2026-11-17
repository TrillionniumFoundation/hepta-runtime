"""Actual fresh HIA graph build and complete compiler custody; no Rust."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import COMPILER_COMMIT,COMPILER_TREE,BASE,put,read,require,sha,source_evidence

def git(root, *arguments):
    return subprocess.run(["git", "-C", str(root), *arguments], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout

def tree_entries(raw):
    entries = {}
    offset = 0
    while offset < len(raw):
        space = raw.index(b" ", offset)
        zero = raw.index(b"\0", space)
        mode = raw[offset:space].decode()
        name = raw[space + 1:zero].decode()
        oid = raw[zero + 1:zero + 21].hex()
        require(len(oid) == 40 and name not in entries, "Git tree record")
        entries[name] = (mode, oid)
        offset = zero + 21
    require(offset == len(raw), "Git tree extent")
    return entries

def compiler_custody(hepta, identity, capture):
    objects = {}

    def get_object(kind, oid):
        key = kind + ":" + oid
        if key not in objects:
            raw = git(hepta, "cat-file", kind, oid)
            actual = hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            require(actual == oid, "Git compiler object identity")
            put(capture / "compiler-git" / (oid + "." + kind), raw)
            objects[key] = raw
        return objects[key]

    commit = get_object("commit", COMPILER_COMMIT)
    require(commit.startswith(b"tree " + COMPILER_TREE.encode() + b"\n"), "compiler commit tree")
    rows = {}
    for relative, digest in identity["files"].items():
        parts = relative.split("/")
        current = COMPILER_TREE
        for name in parts[:-1]:
            mode, current = tree_entries(get_object("tree", current))[name]
            require(mode == "40000", "compiler directory mode")
        mode, oid = tree_entries(get_object("tree", current))[parts[-1]]
        require(mode in ("100644", "100755"), "compiler input mode")
        raw = read(hepta / relative)
        require(sha(raw) == digest, "compiler input changed after fresh build")
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid, "compiler input Git blob")
        path = capture / "compiler-source" / relative
        put(path, raw)
        path.chmod(0o755 if mode == "100755" else 0o644)
        rows[relative] = {"bytes": len(raw), "sha256": digest, "git_blob": oid, "git_mode": mode}
    put(capture / "compiler-source.json", {"commit": COMPILER_COMMIT, "tree": COMPILER_TREE,
        "files": rows, "git_objects": sorted(objects)})


def main(args):
    root,hepta,capture=args.source_root.resolve(),args.hepta.resolve(),args.capture.absolute()
    source_evidence(root,args.source_pins_sha256)
    sys.path.insert(0,str(root/'scripts'))
    from hia_native_build import NativeBuild
    from hia_native_owner_export_build import build_owner_export,admitted_profile,make_frame,PACKER_SHA
    from hia_native_loader import NativeModule
    from hia_native_authority_layout import validate_authority_layout
    build_root=capture/'build'
    require(not build_root.exists(),'fresh graph output already exists')
    if args.bootstrap_cache is not None:
        import shutil
        shutil.copytree(args.bootstrap_cache,build_root/'bootstrap')
    manifest=build_owner_export(hepta,build_root,source_root=root)
    builder=NativeBuild(hepta,build_root)
    fixture=builder.compile('scope-entropy-fixture',root/'tests/hia_native/scope_entropy_fixture.hepta',standalone=None)
    profile,provenance,_=admitted_profile(root)
    modules={}
    for row in profile['members']:
        name='composition-'+row['source_sha256'][:24]
        modules[row['source']]=(build_root/'modules'/name/'manifest.json').relative_to(capture).as_posix()
    modules['native/caller_owner_export_packer.hepta']=(build_root/'modules'/('composition-'+PACKER_SHA[:24])/'manifest.json').relative_to(capture).as_posix()
    modules['tests/hia_native/scope_entropy_fixture.hepta']=fixture.relative_to(capture).as_posix()
    images=[read(capture/modules[row['source']]).decode() for row in profile['members']]
    actual_images=[read((capture/modules[row['source']]).parent/json.loads(meta)['image']) for row,meta in zip(profile['members'],images,strict=True)]
    frame=make_frame(profile,actual_images)
    pack_manifest=capture/modules['native/caller_owner_export_packer.hepta']
    with NativeModule(pack_manifest,manifest_sha256=sha(read(pack_manifest))) as pack:
        code,output,workspace=pack.invoke_raw(frame,output_capacity=8<<20,workspace_capacity=1<<20,
            output_fill=0xcc,workspace_fill=0xa7)
    graph=json.loads(read(manifest));executable=read(manifest.parent/graph['executable'])
    require(code==len(executable) and output[:code]==executable and output[code:]==b'\xcc'*(len(output)-code),
        'actual complete pack output differs')
    layout=validate_authority_layout(executable,frame,profile,provenance)
    for name,raw in [('input',frame),('output',output),('workspace',workspace)]:put(capture/'pack'/('full-'+name+'.bin'),raw)
    put(capture/'pack/call.json',{'schema':'hepta.runtime.owner-export.pack-call.v2','pid':os.getpid(),
        'code':code,'input_bytes':len(frame),'input_sha256':sha(frame),'output_sha256':sha(output),
        'workspace_sha256':sha(workspace),'output_fill':0xcc,'workspace_fill':0xa7,
        'layout':layout,'packer_manifest_sha256':sha(read(pack_manifest)),
        'complete_observed_packer_calls':1,'builder_packer_calls':1})
    compiler_custody(hepta,builder.identity,capture)
    source_evidence(root,args.source_pins_sha256)
    put(capture/'native-build.json',{'schema':'hepta.runtime.owner-export-build.v2','pid':os.getpid(),
        'ppid':os.getppid(),'pgid':os.getpgid(0),'manifest':manifest.relative_to(capture).as_posix(),
        'manifest_sha256':sha(read(manifest)),'fixture_manifest':fixture.relative_to(capture).as_posix(),
        'fixture_manifest_sha256':sha(read(fixture)),'modules':modules,
        'fresh_bootstrap':args.bootstrap_cache is None,'reused_bootstrap':args.bootstrap_cache is not None,
        'matching_source_cold_qualified':False,'compiler_source_identity':builder.identity,
        'source_pins_sha256':args.source_pins_sha256})
    print('OWNER_EXPORT_HIA_GRAPH_BUILD_PASS',flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('source-root','hepta','capture'):p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--source-pins-sha256',required=True)
    p.add_argument('--bootstrap-cache',type=Path)
    main(p.parse_args())

