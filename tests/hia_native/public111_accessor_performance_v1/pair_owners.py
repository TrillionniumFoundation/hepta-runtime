"""CI-only full-buffer old/new observation of two fixed normal protocol owners."""
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
import argparse,gzip,hashlib,importlib.util,json,os,struct,time
def pin(p):
 with p.open("rb") as f:d=hashlib.file_digest(f,"sha256").hexdigest()
 return {"bytes":p.stat().st_size,"sha256":d}
def save(root,name,raw):
 p=root/name
 with p.open("xb") as out:
  with gzip.GzipFile(filename="",mode="wb",fileobj=out,compresslevel=1,mtime=0) as stream:stream.write(raw)
 return {"file":name,"stored":pin(p),"raw":{"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}}
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for key in ("baseline","candidate","loader","inputs","output"):p.add_argument("--"+key,type=Path,required=True)
 p.add_argument("--sequence",type=int,required=True);p.add_argument("--component",choices=("message","value"),required=True);a=p.parse_args()
 assert os.environ.get("GITHUB_ACTIONS")=="true" and not a.output.exists();a.output.mkdir(parents=True)
 spec=importlib.util.spec_from_file_location("_exact_native_byte_loader",a.loader);loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
 lines=(a.inputs/f"sequence-{a.sequence}.stdin").read_bytes().splitlines(keepends=True);assert len(lines)==3
 payload=lines[2];tag=b"HRCJQ001" if a.component=="message" else b"HJSVS002"
 wire=tag+struct.pack("<QQ",1,len(payload))+payload
 (a.output/"input.bin").write_bytes(wire)
 md=[json.loads(x.read_bytes()) for x in (a.baseline,a.candidate)]
 assert md[0]["buffer_profile"]==md[1]["buffer_profile"]
 ocap=max(65536,3*len(payload)+1024);wcap=96<<20
 assert all(ocap<=m["output_capacity"] and wcap<=m["workspace_capacity"] for m in md)
 cases=[("normal",ocap,wcap,0),("seeded",ocap,wcap,165),("initial-workspace",ocap,20480 if a.component=="value" else 256,0),("small-output",32,wcap,0)]
 observations=[]
 with loader.NativeModule(a.baseline,manifest_sha256=pin(a.baseline)["sha256"]) as old,loader.NativeModule(a.candidate,manifest_sha256=pin(a.candidate)["sha256"]) as new:
  for label,outcap,workcap,fill in cases:
   sides=[]
   for side,module in (("before",old),("after",new)):
    started=time.monotonic_ns()
    code,output,workspace=module.invoke_raw(wire,output_capacity=outcap,workspace_capacity=workcap,output_fill=fill,workspace_fill=fill)
    elapsed=time.monotonic_ns()-started
    row={"side":side,"actual_return":code,"elapsed_ns":elapsed,"output":save(a.output,label+"-"+side+"-output.gz",output),"workspace":save(a.output,label+"-"+side+"-workspace.gz",workspace)}
    sides.append(row)
   assert sides[0]["actual_return"]==sides[1]["actual_return"]
   assert sides[0]["output"]["raw"]==sides[1]["output"]["raw"] and sides[0]["workspace"]["raw"]==sides[1]["workspace"]["raw"]
   observations.append({"case":label,"output_capacity":outcap,"workspace_capacity":workcap,"fill":fill,"sides":sides})
  assert observations[0]["sides"][0]["actual_return"]<0xffff0000
 report={"schema":"hepta.runtime.fixed-accessor-paired.v1","status":"FOUR_COMPLETE_BUFFER_PAIRS_OBSERVED","component":a.component,"sequence":a.sequence,
  "input":pin(a.output/"input.bin"),"loader":pin(a.loader),"manifests":{"before":pin(a.baseline),"after":pin(a.candidate)},
  "source_sha256":{"before":md[0]["source_sha256"],"after":md[1]["source_sha256"]},"image_sha256":{"before":md[0]["image_sha256"],"after":md[1]["image_sha256"]},
  "observations":observations,"native_calls":8,"full_public_domain_qualified":False,"rust_executions":0}
 (a.output/"PAIRS.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
