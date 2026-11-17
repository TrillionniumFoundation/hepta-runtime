"""Re-read every retained paired output/workspace byte without executing code."""
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
import argparse,gzip,hashlib,json
def pin(p):
 with p.open("rb") as f:d=hashlib.file_digest(f,"sha256").hexdigest()
 return {"bytes":p.stat().st_size,"sha256":d}
def read(root):
 report=json.loads((root/"PAIRS.json").read_bytes())
 assert report["schema"]=="hepta.runtime.fixed-accessor-paired.v1" and report["native_calls"]==8
 assert pin(root/"input.bin")==report["input"]
 seen={"input.bin","PAIRS.json"};logical=0
 for row in report["observations"]:
  assert len(row["sides"])==2 and [x["side"] for x in row["sides"]]==["before","after"]
  before,after=row["sides"];assert before["actual_return"]==after["actual_return"]
  for key in ("output","workspace"):
   sides=[]
   for side in row["sides"]:
    item=side[key];name=item["file"];assert name not in seen and Path(name).name==name;seen.add(name)
    p=root/name;assert pin(p)==item["stored"]
    with gzip.open(p,"rb") as f:raw=f.read()
    assert {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}==item["raw"]
    assert len(raw)==row[key+"_capacity"];logical+=len(raw);sides.append(raw)
   assert sides[0]==sides[1]
 assert [r["case"] for r in report["observations"]]==["normal","seeded","initial-workspace","small-output"]
 assert {p.name for p in root.iterdir()}==seen
 return {"status":"COMPLETE_PAIR_BUFFERS_READ_ONLY_PASS","sequence":report["sequence"],"component":report["component"],"logical_bytes":logical,"files":len(seen),"cases":4,"native_calls_retained":8,
  "native_or_rust_reader_executions":0,"source_sha256":report["source_sha256"],"image_sha256":report["image_sha256"]}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--capture",type=Path,required=True);a=p.parse_args()
 print(json.dumps(read(a.capture.resolve(strict=True)),sort_keys=True))
if __name__=="__main__":main()
