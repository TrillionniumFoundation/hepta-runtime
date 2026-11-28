#!/usr/bin/env python3
"""Author the explicit Rust 1.95 Linux statx policy and complete stat64 mapping."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,sys
sys.dont_write_bytecode=True
def sha(raw): return hashlib.sha256(raw).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    args=p.parse_args();root=args.source.resolve(strict=True);output=args.output.absolute()
    assert not output.exists()
    support_path=root/"authoring/public_publication_v1/source_support.py"
    spec=importlib.util.spec_from_file_location("namespace_metadata_author_support",support_path)
    support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
    source=(root/"native/runtime_mcp_catalog_ninth.hepta").read_bytes()
    assert sha(source)=="c555bec54b9f7affd6ea85b8db005e334fecc4388897433b7b03ed557aa585c8"
    comp=json.loads((root/"native/runtime_mcp_catalog_ninth_composition.json").read_bytes())
    roots={"word":comp["aliases"]["load"],"get":comp["aliases"]["get"],"put":comp["aliases"]["put"]}
    reference=(root/"authoring/namespace_metadata/reference/rust195-unix.rs").read_bytes()
    assert len(reference)==88655 and sha(reference)=="77c6419ee048c348d9ed4bef226ce6ceb735d6077d0eb9f6bcac0ef46fa7b86d"
    constants={name:support.WORD(word) for name,word in (
        ("REQUEST","HNSMQ001"),("RESPONSE","HNSMR001"),("ACK","HNSMA001"),("EFFECT","HNSME001"))}
    constants.update(INVALID=0xffffffff,RESOURCE=0xfffffffe,ACTION=0xffffffb1,
        MAX_U64=18446744073709551615,ERROR_MIN=18446744073709547521)
    glibc_references={'glibc-statx.c': {'bytes': 1294, 'sha256': '0afda6dd218f2660768ce1f5c3f384b64c47949a62b4f241ec5956022906c38f', 'git_blob': '18f13153c7d591d8cd85b4c336704600f11bc6dd', 'upstream_url': 'https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/statx.c'}, 'glibc-statx-generic.c': {'bytes': 3144, 'sha256': '26dc8764fe83bb43d33cbb7f9b1f82d826d1c2762c241722919ba79b63ef368b', 'git_blob': '087e041b4cabe2422439e0b57af9e2a27be864b6', 'upstream_url': 'https://github.com/bminor/glibc/blob/master/io/statx_generic.c'}, 'COPYING.glibc': {'bytes': 26419, 'sha256': '20e50fe7aae3e56378ebf0417d9de904f55a0e61e4df315333e632a4d3555d95', 'git_blob': 'f6683e74e0f0130f246dbf7054f4cacc88ca84b0', 'upstream_url': 'https://github.com/bminor/glibc/blob/master/COPYING.LESSERv2'}}
    for name,identity in glibc_references.items():
        raw=(root/'authoring/namespace_metadata/reference'/name).read_bytes()
        assert len(raw)==identity['bytes'] and sha(raw)==identity['sha256']
    pseudo=(root/"authoring/namespace_metadata/policy.pseudo").read_bytes()
    raw,names,proof=support.compile_new(support.tools(args.hepta),source,roots,pseudo.decode(),constants,"namespace_metadata")
    proof.update(schema="hepta.runtime.namespace-metadata-source.v1",aliases=names,constants=constants,
        glibc_statx_references=glibc_references,
        rust_reference={"repository":"rust-lang/rust","tag":"1.95.0","path":"library/std/src/sys/fs/unix.rs",
            "git_blob":"7db474544f04abc75e2d66ec007ebe4799a491d3",**support.identity(reference)},
        pseudo=support.identity(pseudo),support=support.identity(support_path.read_bytes()),
        policy="Rust 1.95 cache plus GNU statx ENOSYS/newfstatat wrapper; complete stat64/statx conversions; real error and probe calls",
        stat64_mapping_bytes=144,shared_cache_bytes=1,source_native_qualified=False,
        syscall_effects_qualified=False,whole_namespace_qualified=False)
    output.mkdir(parents=True)
    (output/"namespace_metadata.hepta").write_bytes(raw)
    (output/"namespace_metadata_composition.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    print(json.dumps({key:proof[key] for key in ("source","functions","blocks","operations")},sort_keys=True))
if __name__=="__main__":main()
