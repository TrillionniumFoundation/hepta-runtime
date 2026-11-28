"""Install a private source revision for the shared text constructor public edge."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil

BASE_BINDING="07530ce3f0803b1a42c2f74927237a371d78b1f81454101e788c9e420506b404"
CORE_SOURCE="3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("baseline","core","overlay","output"):
        p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    baseline,core,overlay,output=(getattr(a,n).resolve() for n in ("baseline","core","overlay","output"))
    raw=(baseline/"native/runtime_mcp_sources.json").read_bytes()
    if sha(raw)!=BASE_BINDING:
        raise ValueError("qualified 79 source binding differs")
    binding=json.loads(raw)
    for rel,row in binding["sources"].items():
        data=(baseline/rel).read_bytes()
        if row!=dict(bytes=len(data),sha256=sha(data)):
            raise ValueError(("baseline source differs",rel))
    if sha((core/"native/text_result_constructor.hepta").read_bytes())!=CORE_SOURCE:
        raise ValueError("shared constructor changed")
    shutil.copytree(baseline,output)
    added=[]
    for source in (core,overlay):
        for path in sorted(source.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                rel=path.relative_to(source)
                target=output/rel
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(path.read_bytes())
                added.append(str(rel))
    edits=json.loads((overlay/"scripts/public_constructor_source_edits.json").read_bytes())
    for rel,changes in edits.items():
        path=output/rel
        text=path.read_text()
        for change in changes:
            old,new=change["old"],change["new"]
            if text.count(old)!=1:
                raise ValueError(("source anchor differs",rel,old[:100],text.count(old)))
            text=text.replace(old,new,1)
        path.write_text(text)
    names=(set(binding["sources"])|set(added))-{"native/runtime_mcp_sources.json"}
    binding["sources"]={rel:dict(bytes=len((output/rel).read_bytes()),sha256=sha((output/rel).read_bytes()))
                        for rel in sorted(names)}
    binding["target_text_constructor_extension"]=dict(
        baseline_source_binding_sha256=BASE_BINDING,constructor_source_sha256=CORE_SOURCE,
        physical_images=80,engine_slots=47,frontend_local_child=10,constructor_slot=46,
        raw_publisher_kind=3,ordinary_public_qualified=False,actual_target_rust_compared=False,
        general_target_response_owner_integrated=False,full_sdk_qualified=False)
    (output/"native/runtime_mcp_sources.json").write_text(json.dumps(binding,sort_keys=True,indent=2)+"\n")
    report=dict(schema="hepta.runtime.public-constructor-install.v1",
        baseline_source_binding_sha256=BASE_BINDING,
        destination_source_binding_sha256=sha((output/"native/runtime_mcp_sources.json").read_bytes()),
        constructor_source_sha256=CORE_SOURCE,
        unchanged_catalog=(output/"native/runtime_mcp_catalog_ninth.hepta").read_bytes()==(baseline/"native/runtime_mcp_catalog_ninth.hepta").read_bytes(),
        unchanged_connection=(output/"native/runtime_mcp_protocol.hepta").read_bytes()==(baseline/"native/runtime_mcp_protocol.hepta").read_bytes(),
        unchanged_publication_owner=(output/"native/result_publication.hepta").read_bytes()==(baseline/"native/result_publication.hepta").read_bytes(),
        native_executed=False,rust_executed=False,full_sdk_qualified=False)
    (output.parent/(output.name+"-INSTALL.json")).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report,sort_keys=True))


if __name__=="__main__":
    main()

