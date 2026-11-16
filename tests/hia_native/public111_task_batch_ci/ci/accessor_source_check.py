"""Bind current G1/Value to the exact fixed-accessor proof and prior sources."""
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
import argparse,copy,hashlib,json,re,shutil,sys
sys.dont_write_bytecode=True
AUTHOR="73ed04df99353d00c2a48e5f5f972b650e3dae44f187f03edd3955fc477f3995"
PROOF="7a8b139fc3c6ced9fcfc51124c105f0ee5d16fe8ffd71339b06e7164607f3aee"
BASE_COMPOSITION="059338b25022129d79a61866f9e0af31528654a552f73a0ade8bd0ae9f21b06c"
CURRENT_COMPOSITION="af8ffd948e8cc616933e58b6c224a33021ef1cbeddb6f1fadf12d337ce2b3aa8"
SOURCES={
 "native/sdk_message_target.hepta":("4346674242b7f00cd97cee2b04e958a7552923623a79a1355d469c251add2968","3246ce5e5975851c71a4f487408f8ea5a69983f711614ea7d49d58c720be4961"),
 "native/serde_json_span.hepta":("7a9355792f5044c9887c4194df5bc169664cf08fa8d084e8480c941fa2416a41","eb7bf96e7944d8d69fa0ee441ecbf3fc2a79daaa233a3f9706f0fc324eb39f7d")}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
def canon(v):return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def require(ok,message):
 if not ok:raise ValueError(message)
def current_composition(previous):
 value=json.loads(previous)
 value.update(schema="hepta.sdk-request-tasks.composition.v4",previous_composition_sha256=sha(previous),
  previous_required_message_source_sha256=value["required_message_source_sha256"],
  required_message_source_sha256=SOURCES["native/sdk_message_target.hepta"][1],
  message_accessor_source_proof="native/fixed_accessor_contraction.json",message_accessor_source_proof_sha256=PROOF,
  message_dependency_rebinding_only=True,registry_owner_bytes_changed_by_message_rebinding=False,
  public_admission_proof_scope="retained one-byte registry delta; current G1 dependency independently bound by fixed_accessor_contraction.json")
 return encoded(value)
def verify(package,hepta=None):
 package=Path(package);graph=package/"graph/source";baseline=package/"ci/accessor-baseline"
 author_path=graph/"authoring/sdk_accessor/author_accessors.py";author_raw=author_path.read_bytes()
 proof_raw=(graph/"native/fixed_accessor_contraction.json").read_bytes()
 require(sha(author_raw)==AUTHOR and sha(proof_raw)==PROOF,"fixed accessor author/proof identity")
 proof=json.loads(proof_raw)
 require(proof["author_sha256"]==AUTHOR and proof["schema"]=="hepta.runtime.fixed-accessor-call-contraction.v1","fixed accessor proof provenance")
 require(proof["full_public_domain_qualified"] is False and proof["fresh_ci_qualified"] is False
  and proof["no_native_or_rust_executions"] is True,"source proof must not become runtime qualification")
 rows={}
 for name,(before_hash,after_hash) in SOURCES.items():
  before=(baseline/name).read_bytes();after=(graph/name).read_bytes()
  require(sha(before)==before_hash and sha(after)==after_hash,"complete old/new accessor source: "+name)
  item=proof["changes"][name]
  require(item["before_sha256"]==before_hash and item["after_sha256"]==after_hash
   and item["after_bytes"]==len(after) and item["inverse_recovers_full_source"] is True
   and item["ordinary_input_predicates_added"] is False and item["parser_or_formatter_algorithm_changed"] is False,
   "accessor proof/actual source binding")
  rows[name]={"before_sha256":before_hash,"after_sha256":after_hash,"before_bytes":len(before),"after_bytes":len(after)}
 previous=(baseline/"native/sdk_request_task_composition.json").read_bytes()
 current=(graph/"native/sdk_request_task_composition.json").read_bytes()
 require(sha(previous)==BASE_COMPOSITION and sha(current)==CURRENT_COMPOSITION
  and current==current_composition(previous),"current registry message dependency composition")
 if hepta is not None:
  scope={"__name__":"_fixed_accessor_author","__file__":str(author_path)}
  exec(compile(author_raw,str(author_path),"exec"),scope)
  sys.path.insert(0,str(Path(hepta).resolve(strict=True)))
  from hepta.hia_agent_assembly import assemble_program
  for name in SOURCES:
   old=(baseline/name).read_bytes();raw=(graph/name).read_bytes();spec=scope["SPECS"][name]
   text,patches,helpers=scope["generate"](old.decode(),spec)
   require(text.encode()==raw,"full accessor author reproduction")
   before=assemble_program(old).as_dict();after=assemble_program(raw).as_dict()
   require(before["schema"]==after["schema"] and before["module"]==after["module"],"module/schema retained")
   b={f["name"]:f for f in before["functions"]};c={f["name"]:f for f in after["functions"]}
   require(b.keys()==c.keys(),"complete function set retained")
   for fn in b:
    require(all(b[fn][k]==c[fn][k] for k in ("params","returns","effects","entry")),"function signature retained")
    require(len(b[fn]["blocks"])==len(c[fn]["blocks"]),"complete CFG block set retained")
    for x,y in zip(b[fn]["blocks"],c[fn]["blocks"],strict=True):
     require(x["id"]==y["id"] and x["params"]==y["params"],"block declaration retained")
     if fn not in helpers:require(x["term"]==y["term"],"all caller CFG edges retained")
   expected=dict(before_sha256=sha(old),after_sha256=sha(raw),after_bytes=len(raw),
    wrappers=spec["inline"],contracted_call_sites=len(patches),inverse_recovers_full_source=True,
    all_function_signatures_and_cfg_edges_retained=True,
    helper_proofs={k:{"before_sha256":sha(v["before"].encode()),"after_sha256":sha(v["after"].encode()),"ordered_symbolic_byte_trace_sha256":v["ordered_symbolic_byte_trace_sha256"]} for k,v in helpers.items()},
    changed_functions={n:{"before_ast_sha256":sha(canon(b[n])),"after_ast_sha256":sha(canon(c[n]))} for n in b if b[n]!=c[n]},
    exact_retained_functions={n:sha(canon(b[n])) for n in b if b[n]==c[n]},
    patches_sha256=sha(canon(patches)),ordinary_input_predicates_added=False,parser_or_formatter_algorithm_changed=False)
   require(expected==proof["changes"][name],"complete independently regenerated accessor source proof")
 return {"status":"EXACT_ACCESSOR_SOURCE_AND_REGISTRY_DEPENDENCY_PASS","proof_sha256":PROOF,"author_sha256":AUTHOR,
  "sources":rows,"previous_composition_sha256":BASE_COMPOSITION,"current_composition_sha256":CURRENT_COMPOSITION,
  "original_registry_hia_unchanged":True,"native_or_rust_executed":False,"full_public_domain_qualified":False}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--package",type=Path,required=True);p.add_argument("--hepta",type=Path)
 a=p.parse_args();print(json.dumps(verify(a.package,a.hepta),sort_keys=True))
if __name__=="__main__":main()
