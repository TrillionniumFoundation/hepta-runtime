"""CI-only accessor contraction, full-buffer pairs, and exact request timings."""
# Copyright 2026 Muvon Un Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from pathlib import Path
import argparse,hashlib,json,os,shutil,sys
CHANGED={
 "target_message":("native/sdk_message_target.hepta","3246ce5e5975851c71a4f487408f8ea5a69983f711614ea7d49d58c720be4961"),
 "wide_value":("native/serde_json_span.hepta","eb7bf96e7944d8d69fa0ee441ecbf3fc2a79daaa233a3f9706f0fc324eb39f7d")}
def pin(path):
 with path.open("rb") as f:d=hashlib.file_digest(f,"sha256").hexdigest()
 return {"bytes":path.stat().st_size,"sha256":d}
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ("source","package","build","failure","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
 a=p.parse_args();source=a.source.resolve(strict=True);package=a.package.resolve(strict=True)
 build=a.build.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.resolve()
 assert os.environ.get("GITHUB_ACTIONS")=="true" and not out.exists()
 declared=json.loads((source/"SOURCE.json").read_bytes())
 actual={q.relative_to(source).as_posix():pin(q) for q in sorted(source.rglob("*")) if q.is_file() and q.name!="SOURCE.json"}
 assert actual==declared["files"]
 corpus=json.loads((source/"CORPUS.json").read_bytes());out.mkdir(parents=True)
 sys.path.insert(0,str(package/"ci"));from common import command,put
 py=[sys.executable,"-I","-S","-B"]
 command(out,"recover-exact-corpus",py+[str(source/"recover_corpus.py"),"--source",str(source),"--failure",str(a.failure.resolve(strict=True)),"--output",str(out/"inputs")])
 command(out,"read-original-complete-build",py+[str(package/"ci/read_build.py"),"--package",str(package),"--build",str(build),"--manifest-sha256",corpus["base_package_sha256"]])
 put(out/"ORIGIN.json",{"diagnostic_source":pin(source/"SOURCE.json"),"corpus":pin(source/"CORPUS.json"),
  "base_build_archive":corpus["build_artifact"],"head":os.environ["GITHUB_SHA"],"run_id":os.environ["GITHUB_RUN_ID"],
  "changed_direct_hia_sources":CHANGED,"unchanged_direct_hia_members":101,"unchanged_packed_hia_members":8,
  "all_hia_bytes_unchanged":False,"full_public_domain_qualified":False,
  "retained_compilation_run_id":43961663648,"same_current_ci_all_leaves_fresh":False,"matching_source_cold_qualified":False})
 profiled=out/"profile-source"
 command(out,"author-fixed-observations",py+[str(source/"author_engine_profile.py"),"--source",str(package/"graph/source"),"--output",str(profiled)])
 generated=out/"optimized-source"
 command(out,"prove-and-author-accessor-contraction",py+[str(source/"author_accessors.py"),"--baseline",str(profiled),"--expected",str(source/"expected"),"--output",str(generated),"--hepta",str(hepta)])
 production=json.loads((build/"production/build/public-task-batch/manifest.json").read_bytes())
 before={r["name"]:r for r in production["members"]};assert len(before)==103
 original_manifests={n:build/"production/build/modules"/("public-task-batch-"+n.replace("_","-"))/"manifest.json" for n in before}
 members={n:str(original_manifests[n]) for n in before if n not in CHANGED}
 assert len(members)==101;put(out/"retained-ci-members.json",members)
 target=out/"build";target.mkdir();shutil.copytree(build/"production/worker/build/bootstrap",target/"bootstrap")
 command(out,"build-two-and-pack-fixed-profile",py+[str(generated/"scripts/public_nine_build.py"),"--hepta",str(hepta),"--build",str(target),"--name","profile",
  "--bellman-port-build",str(build/"production/port/build-v3"),"--bellman-port-package",str(generated/"runtime_support/bellman_port"),
  "--bellman-worker-build",str(build/"production/worker"),"--member-manifests-json",str(out/"retained-ci-members.json"),"--private-pump-fixture","--private-pump-trace"])
 manifest=target/"profile/manifest.json";m=json.loads(manifest.read_bytes());after={r["name"]:r for r in m["members"]}
 assert len(after)==103 and after.keys()==before.keys()
 assert {n for n,r in after.items() if r["fresh_compile"]}==CHANGED.keys()
 fields=("name","source","source_sha256","manifest_sha256","image_sha256","image_bytes","buffer_profile")
 for n,r in after.items():
  if n in CHANGED:
   assert (r["source"],r["source_sha256"])==CHANGED[n]
   module=Path(r["manifest"]);assert module==target/"modules"/("profile-"+n.replace("_","-"))/"manifest.json"
   md=json.loads(module.read_bytes())
   assert pin(module)["sha256"]==r["manifest_sha256"]
   assert pin(module.parent/md["image"])=={"bytes":r["image_bytes"],"sha256":r["image_sha256"]}
   assert (module.parent/md["source"]).read_bytes()==(generated/r["source"]).read_bytes()
  else:assert {k:r[k] for k in fields}=={k:before[n][k] for k in fields}
 assert m["packed_capabilities"]["57"]["elf_sha256"]==production["packed_capabilities"]["57"]["elf_sha256"]
 binary=target/"profile"/m["elf"];assert pin(binary)=={"bytes":m["elf_bytes"],"sha256":m["elf_sha256"]}
 pairs=[]
 for row in corpus["rows"]:
  for component,member in (("message","target_message"),("value","wide_value")):
   label="pair-"+row["name"]+"-"+component;folder=out/"pairs"/label
   # These two leaf modules have no external child process. The retained 60s
   # native deadline therefore covers the whole single observer process.
   command(out,label,["timeout","--signal=KILL","60s",*py,str(source/"pair_owners.py"),
    "--baseline",str(original_manifests[member]),"--candidate",after[member]["manifest"],
    "--loader",str(generated/"scripts/hia_native_loader.py"),"--inputs",str(out/"inputs"),
    "--output",str(folder),"--sequence",str(row["sequence"]),"--component",component])
   command(out,"read-"+label,py+[str(source/"read_pairs.py"),"--capture",str(folder)])
   pairs.append(json.loads((out/"processes"/("read-"+label+".stdout")).read_bytes()))
 reports=[]
 for row in corpus["rows"]:
  name=row["name"];capture=out/name
  command(out,"observe-"+name,py+[str(source/"observe.py"),"--binary",str(binary),"--elf-sha256",m["elf_sha256"],"--input",str(out/"inputs"/(name+".stdin")),"--output",str(capture),"--trace"])
  command(out,"read-"+name,py+[str(source/"read_profile.py"),"--source",str(source),"--inputs",str(out/"inputs"),"--capture",str(capture),"--manifest",str(manifest),"--name",name])
  reports.append(json.loads((out/"processes"/("read-"+name+".stdout")).read_bytes()))
 result={"status":"ACCESSOR_CONTRACTION_PAIRED_AND_THREE_REQUESTS_PROFILED","cases":len(reports),"hia_images_changed":2,"direct_leaf_recompiles":2,
  "retained_direct_images":101,"retained_packed_hia_images":8,"paired_full_buffer_cases":24,"paired_actual_native_calls":48,
  "paired_reports":pairs,"mechanical_profile_repacked":True,"all_three_complete_wire_preserved":True,"reports":reports,
  "whole_1394_or_async_qualified":False,"per_process_seconds":60,"original_1394_process_seconds":180}
 put(out/"PROFILE.json",result);print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
