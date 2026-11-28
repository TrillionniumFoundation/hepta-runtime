"""Exact source and production graph admission for the public read controls."""
from pathlib import Path
import hashlib,json,os,sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"scripts"))
from public_nine_build import source_check
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
    raw=Path(path).read_bytes()
    return {"bytes":len(raw),"sha256":sha(raw)}
def load(label,*,create=True):
    if sys.flags.isolated!=1 or sys.flags.optimize!=0:
        raise ValueError("public controls require isolated Python with assertions enabled")
    output=Path(os.environ["HIA_PUBLIC_READ_OUTPUT"]).resolve(strict=True)
    manifest=Path(os.environ["HIA_PUBLIC_READ_MANIFEST"]).resolve(strict=True)
    document=json.loads(manifest.read_bytes())
    if document["schema"]!="hepta.runtime.public-task-batch-extract-build.v1" or document["status"]!="PASS":
        raise ValueError("actual complete public build is required")
    if (document["physical_images"]!=130 or document["runtime_hia_images"]!=162
            or len(document["members"])!=127):
        raise ValueError("qualified public read/catalog graph differs")
    if any(document[name]is not False for name in
           ("private_instance_fixture","private_task_pump_fixture","private_task_pump_trace","actual_fixture_private_selectors")):
        raise ValueError("a private fixture cannot stand in for the default public entrypoint")
    if Path(document["source_root"]).resolve(strict=True)!=ROOT:
        raise ValueError("build and control source roots differ")
    binding=source_check(ROOT)
    if document["source_binding"]!=binding:
        raise ValueError("complete public source binding differs")
    elf=manifest.parent/document["elf"]
    identity=pin(elf)
    if identity!={"bytes":document["elf_bytes"],"sha256":document["elf_sha256"]}:
        raise ValueError("complete production executable differs")
    dependency=document["public_catalog_dependency"]
    catalog_manifest=Path(dependency["build_manifest"]).resolve(strict=True)
    if pin(catalog_manifest)!=dependency["build_manifest_pin"]:
        raise ValueError("actual embedded catalog build differs")
    folder=output/label
    if folder.exists():raise ValueError("public control evidence must be fresh")
    if create:folder.mkdir()
    normalized={"status":"PASS","elf":str(elf),"elf_sha256":identity["sha256"],
        "source_binding":binding["manifest_sha256"],"manifest":str(manifest),
        "catalog_build":str(catalog_manifest.parent)}
    return output,ROOT,folder,normalized,elf,identity["sha256"]
