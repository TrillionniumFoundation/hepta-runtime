from pathlib import Path
import hashlib,json,shutil,sys
sys.dont_write_bytecode=True
base=Path("/workspace/scratch/6780eb0cbcc3/audit-store-lock-work-v1")
source=base/"callable-source"
sys.path.insert(0,str(source/"scripts"))
from hia_native_build import NativeBuild
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
expected="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
old=base/"controller-build-v1/bootstrap"
out=base/"callable-build-v1"
assert not out.exists()
for label in ("B1","B2","B3"):assert digest(old/(label+".image.bin"))==expected
out.mkdir()
shutil.copytree(old,out/"bootstrap")
old_files={p.relative_to(old).as_posix():p.read_bytes() for p in old.rglob("*") if p.is_file()}
new=out/"bootstrap"
assert set(old_files)=={p.relative_to(new).as_posix() for p in new.rglob("*") if p.is_file()}
for name,raw in old_files.items():
 assert (new/name).read_bytes()==raw
 assert (new/name).stat().st_mode==(old/name).stat().st_mode
hia=source/"native/audit_controller_callable.hepta"
assert digest(hia)=="fb452914cc38cdfcffb9cb1b6ca0a01328a893c5976eb2eb3144befdd7c3c54d"
builder=NativeBuild("/workspace/scratch/6780eb0cbcc3/Hepta-cold-close",out)
assert digest(builder.bootstrap())==expected
manifest=builder.compile("audit-controller-callable",hia,standalone=None,buffer_profile="history.v1")
assert digest(hia)=="fb452914cc38cdfcffb9cb1b6ca0a01328a893c5976eb2eb3144befdd7c3c54d"
image=manifest.parent/"module.image.bin"
report=dict(schema="hepta.audit-callable.compile-only.v1",source_head="f57d88a98f043cb8ef2ac668776c4fd67b45ca59",source_sha256=digest(hia),compiler_sha256=expected,compiler_mode="copied complete retained B1/B2/B3 and reverification",image=dict(bytes=image.stat().st_size,sha256=digest(image)),runtime_semantic_execution=False,rust_execution=False,whole_runtime_replaced=False)
(out/"BUILD.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
print(json.dumps(report,sort_keys=True))
