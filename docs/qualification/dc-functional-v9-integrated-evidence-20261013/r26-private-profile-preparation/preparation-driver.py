#!/usr/bin/env python3
"""Owned private profile preparation: no activation, token read or service control."""
import sys,pathlib,json,hashlib,shlex,copy,os,stat
F=pathlib.Path("/home/qian-qi/hepta-runtime-v9-code-frozen-5037262-20261013")
sys.path.insert(0,str(F/"deploy"))
import stage_dc_successor as S
import preflight_dc_successor as P
import yaml
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v9-integrated-evidence-20261013/r26-private-profile-preparation"
DEST=pathlib.Path("/home/qian-qi/hepta-runtime-successor-v9-private-profile-5037262-20261013-r1")
STAGE=pathlib.Path("/home/qian-qi/hepta-runtime-successor-v9-stage-5037262-20261013-r1/manifest.json")
PIN="70357b2065afa9a9f9b5206047bf4134365b540685ac95e2e2588361b0d89689"
def unique(pairs):
 result={}
 for k,v in pairs:
  if k in result: raise ValueError("duplicate configuration field")
  result[k]=v
 return result
class Loader(yaml.SafeLoader):
 pass
def yaml_unique(loader,node,deep=False):
 return unique(loader.construct_pairs(node,deep=deep))
Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,yaml_unique)
def parse(raw):
 text=raw.decode("utf-8")
 if text.lstrip().startswith("{"):
  return json.loads(text,object_pairs_hook=unique),"json"
 for token in yaml.scan(text):
  if isinstance(token,(yaml.tokens.AliasToken,yaml.tokens.AnchorToken)):
   raise ValueError("configuration alias refused")
 return yaml.load(text,Loader=Loader),"yaml"
def encoded(v):
 return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()
def merged(raw,old_argv,new_argv):
 v,kind=parse(raw)
 if not isinstance(v,dict): raise ValueError("configuration object required")
 n=copy.deepcopy(v)
 commands=n.get("mcp",{}).get("commands",[])
 if len(commands)!=1 or commands[0].get("channel")!="main" or not isinstance(commands[0].get("command"),str):
  raise ValueError("exact single installed command required")
 if shlex.split(commands[0]["command"])!=old_argv:
  raise ValueError("installed command authority differs")
 n["mcp"]["commands"][0]["command"]=shlex.join(new_argv)
 check=copy.deepcopy(n); check["mcp"]["commands"][0]["command"]=v["mcp"]["commands"][0]["command"]
 if check!=v: raise ValueError("configuration fields outside command changed")
 out=encoded(n) if kind=="json" else yaml.safe_dump(n,sort_keys=False,allow_unicode=True).encode()
 if parse(out)[0]!=n: raise ValueError("candidate serialization changes settings")
 return out
def private(pin,label):
 path=S.absolute_path(pin["path"]); P.private_directory(path.parent)
 raw,meta=S.read_pinned(path,pin["sha256"],label)
 if meta["source_mode"]!="0600" or path.stat().st_uid!=os.getuid():
  raise PermissionError("private configuration mode or owner differs")
 return raw,meta
# Test parsing/merge boundaries with synthetic credentials only.
old=["/usr/bin/python3","/fixture/old.py","--stdio"]
new=["/usr/bin/python3","/fixture/new.py","--stdio"]
fixture={"control_plane":{"api_key":"SYNTHETIC_SECRET_ONLY"},"mcp":{"commands":[{"channel":"main","command":shlex.join(old)}]},"other":{"nested":[None,False,17,"preserve"]}}
for raw in (encoded(fixture),yaml.safe_dump(fixture).encode()):
 result=merged(raw,old,new); value,_=parse(result)
 assert value["control_plane"]==fixture["control_plane"] and value["other"]==fixture["other"]
 try: merged(raw,["/wrong"],new)
 except ValueError: pass
 else: raise AssertionError("wrong installed command accepted")
for raw in (b'{"mcp": {}, "mcp": {}}',b"mcp: {}\nmcp: {}\n",b"mcp: &x {}\nother: *x\n"):
 try: parse(raw)
 except ValueError: pass
 else: raise AssertionError("ambiguous profile accepted")
from types import SimpleNamespace
stage,material,stage_info=P.validate_stage(SimpleNamespace(stage_manifest=STAGE,stage_manifest_sha256=PIN,source_root=F))
token_path=stage["baseline"]["auth_token_file"]
services_before=P.service_observation(token_path)
native_pid=int(services_before["units"][P.UNITS[0]]["MainPID"])
native_before=P.process_observation(native_pid)
profile_ref=stage["baseline"]["live_files"]["profile"]
manifest_ref=stage["baseline"]["live_files"]["installed_manifest"]
raw_profile,profile_meta=private(profile_ref,"private installed profile")
raw_manifest,manifest_meta=private(manifest_ref,"private installed manifest")
installed,_=parse(raw_manifest)
assert installed["release"]==str(pathlib.Path(stage["baseline"]["artifacts"]["facade"]["path"]).parent)
old_args=["/usr/bin/python3",stage["baseline"]["artifacts"]["facade"]["path"],"--stdio","--token-file",token_path,"--contract",stage["baseline"]["artifacts"]["contract"]["path"],"--contract-sha256",stage["baseline"]["artifacts"]["contract"]["sha256"],"--acknowledge-full-operator"]
commands=json.loads(material["candidate-commands.json"])
new_args=commands["facade_argv"]
new_profile=merged(raw_profile,old_args,new_args)
activation=json.loads(material["activation-plan.json"])
updates=activation["installed_manifest_field_updates"]
assert set(updates)=={"release","facade_sha256","contract_sha256","tool_contract_catalog_sha256","tools"}
new_manifest=copy.deepcopy(installed)
new_manifest.update(updates)
assert all(new_manifest[k]==v for k,v in installed.items() if k not in updates)
profile_out=DEST/"candidate-profile.yaml"
manifest_out=DEST/"candidate-installed.json"
proof={"schema":"hepta-successor-private-profile-review-v1","status":"HOLD","stage_manifest":{"path":str(STAGE),"sha256":PIN},"source":stage["source"],"inputs":{"profile":profile_ref,"installed_manifest":manifest_ref},"candidate_profile":{"path":str(profile_out),"sha256":S.digest(new_profile) if hasattr(S,"digest") else hashlib.sha256(new_profile).hexdigest(),"bytes":len(new_profile),"mode":"0600"},"candidate_installed_manifest":{"path":str(manifest_out),"sha256":hashlib.sha256(encoded(new_manifest)).hexdigest(),"bytes":len(encoded(new_manifest)),"mode":"0600"},"changed_profile_fields":["mcp.commands[0].command"],"changed_installed_manifest_fields":sorted(updates),"candidate_facade_argv":new_args,"other_profile_fields_preserved":True,"other_installed_manifest_fields_preserved":True,"live_files_changed":False,"services_restarted":False,"app_refreshed":False,"token_read_or_copied":False,"candidate_started":False,"administrator_profile_review_completed":False,"full_dc_replacement_qualified":False,"services_before":services_before}
assert not DEST.exists() and not Q.exists()
assert private(profile_ref,"final profile")[0]==raw_profile
assert private(manifest_ref,"final manifest")[0]==raw_manifest
assert P.service_observation(token_path)==services_before
assert P.process_observation(native_pid)==native_before
P.write_private_bundle(DEST,{"candidate-profile.yaml":(new_profile,0o600),"candidate-installed.json":(encoded(new_manifest),0o600),"review.json":(encoded(proof),0o600)})
assert private(profile_ref,"postpublication profile")[0]==raw_profile
assert private(manifest_ref,"postpublication manifest")[0]==raw_manifest
assert P.service_observation(token_path)==services_before and P.process_observation(native_pid)==native_before
assert profile_out.read_bytes()==new_profile and manifest_out.read_bytes()==encoded(new_manifest)
proof["private_packet_sha256"]=hashlib.sha256((DEST/"review.json").read_bytes()).hexdigest()
proof["public_report_contains_raw_private_profile"]=False
Q.mkdir(mode=0o700)
(Q/"review-public.json").write_bytes(encoded(proof)); (Q/"review-public.json").chmod(0o600)
script=pathlib.Path(__file__)
(Q/"preparation-driver.py").write_bytes(script.read_bytes()); (Q/"preparation-driver.py").chmod(0o600)
(Q/"offline-merge-checks.json").write_bytes(encoded({"synthetic_json_and_yaml_preserve_auth_and_other_settings":True,"wrong_installed_argv_refused":True,"duplicate_json_and_yaml_fields_refused":True,"yaml_aliases_refused":True,"fixture_is_not_live_credential":True}))
print(json.dumps({"private_review":str(DEST/"review.json"),"sha256":proof["private_packet_sha256"],"public_review":str(Q/"review-public.json"),"stage":PIN,"candidate_started":False,"live_files_changed":False,"full_dc_replacement_qualified":False},sort_keys=True))
