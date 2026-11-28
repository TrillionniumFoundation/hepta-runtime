"""Author explicit process policy over captured typed arguments and installed host bytes."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,re,stat,sys
SHA=lambda b:hashlib.sha256(b).hexdigest()
def load_module(name,path,captured):
 import types as _types
 module=_types.ModuleType(name);module.__file__=str(path)
 exec(compile(captured,str(path),"exec"),module.__dict__);return module
def tables(values):
 words=[];layouts={}
 for code,raw in sorted(values.items()):
  raw=raw.encode();layouts[code]=(len(words)<<16)|len(raw)
  for i in range(0,len(raw),8):words.append(int.from_bytes(raw[i:i+8],"little"))
 groups={}
 for code,value in layouts.items():groups.setdefault(code//64,[]).append((code,value))
 lines=["def literal_layout(code: u64) -> u64:"]
 for group in groups:lines += [f"    if code // 64 == {group}:",f"        return layout_{group}(code)"]
 lines+=["    return 0",""]
 for group,items in groups.items():
  lines += [f"def layout_{group}(code: u64) -> u64:"]
  for code,value in items:lines += [f"    if code == {code}:",f"        return {value}"]
  lines += ["    return 0",""]
 lines+=["def data_word(index: u64) -> u64:"]
 for group in range((len(words)+63)//64):
  lines += [f"    if index // 64 == {group}:",f"        return words_{group}(index % 64)"]
 lines+=["    return 0",""]
 for group in range((len(words)+63)//64):
  lines += [f"def words_{group}(index: u64) -> u64:"]
  values=words[group*64:(group+1)*64]
  for i in range(0,len(values),2):
   if i+1<len(values):
    lines += [f"    if index < {i+2}:",f"        return choose(index == {i}, {values[i]}, {values[i+1]})"]
   else:lines += [f"    if index == {i}:",f"        return {values[i]}"]
  lines+=["    return 0",""]
 return "\n".join(lines)
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--source",type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 s=a.source.resolve(strict=True);q=a.output.absolute()
 if q.exists():raise FileExistsError(q)
 names=["authoring/process_owner_v1/validation_author.py","authoring/process_owner_v1/validation.pseudo",
 "authoring/process_owner_v1/author.py","authoring/process_owner_v1/SCHEMAS.json",
 "authoring/public_publication_v1/source_support.py","native/process_params.hepta","native/process_params_composition.json",
 "src/mcp/runtime/jobs.rs","src/mcp/runtime/operator.rs","src/mcp/runtime/config.rs"]
 def take(n):
  p=s/n;st=p.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or p.resolve()!=p:raise ValueError(n)
  b=p.read_bytes()
  after=p.lstat();fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
  if any(getattr(st,k)!=getattr(after,k) for k in fields):raise ValueError("changed "+n)
  return b
 before={n:take(n) for n in names}
 param=load_module("_process_parameter_author",s/names[2],before[names[2]]);support=load_module("_process_source_support",s/names[4],before[names[4]])
 types=json.loads(before[names[3]])["types"]
 field_types=param.fields(types).split("def field_type(",1)[1].split("def required(",1)[0]
 field_types="def field_type("+field_types
 config=before["src/mcp/runtime/config.rs"].decode()
 def original_list(name):
  section=config.split("const "+name+":",1)[1].split("];",1)[0]
  return re.findall(r'"([^"]+)"',section)
 dangerous=original_list("DEFAULT_DANGEROUS");env=original_list("DANGEROUS_ENV")
 errors={
 1:"idempotency_key is mandatory and must contain 1..256 nonblank bytes",
 2:"process execution is disabled for host \x60{a}\x60",
 3:"executable must be a non-empty absolute path",
 4:"executable \x60{a}\x60 must be an absolute path without parent traversal",
 5:"executable intersects protected value \x60{a}\x60 on host \x60{b}\x60",
 6:"executable \x60{a}\x60 is denied on host \x60{b}\x60; use a named privileged_action when configured",
 7:"cwd is required when execution roots are configured for host \x60{a}\x60",
 8:"cwd must be an absolute path",
 9:"cwd \x60{a}\x60 is outside configured execution roots on host \x60{b}\x60",
 10:"cwd intersects protected value \x60{a}\x60 on host \x60{b}\x60",
 11:"arguments may not contain NUL bytes",
 12:"argument intersects protected value \x60{a}\x60 on host \x60{b}\x60",
 13:"environment values may not contain NUL bytes",
 14:"environment variable \x60{a}\x60 is denied on host \x60{b}\x60",
 15:"environment value intersects protected value \x60{a}\x60 on host \x60{b}\x60",
 18:"macOS detached job backend cannot enforce requested CPU/memory limits;              no new job identity allocated or remote launch submitted",
 19:"host \x60{a}\x60 is isolated; operator authority must be configured by its administrator",
 20:"shell source must not contain NUL and is limited to 64 KiB",
 21:"invalid durable job inventory page",
 22:"Command parameter cannot be empty",
 23:"at most 256 arguments are allowed",
 24:"at most 128 environment variables are allowed",
 25:"invalid environment variable name \x60{a}\x60",
 26:"stdin exceeds the 1 MiB limit",
 27:"timeout_seconds must be between 1 and 604800",
 28:"nice must be between 0 and 19",
 29:"cpu_quota_percent must be between 1 and 1000",
 30:"memory_max_bytes must be at least 16 MiB",
 31:"idempotency_key must contain 1..256 bytes"}
 values={}
 for code,message in errors.items():
  first,sep,rest=message.partition("{a}")
  middle,sep2,last=rest.partition("{b}")
  for i,part in enumerate((first,middle,last)):values[code*3+i]=part
 values.update({1000+i:v for i,v in enumerate(dangerous)});values.update({2000+i:v for i,v in enumerate(env)})
 pseudo=before[names[1]].decode()+"\n"+field_types+"\n"+tables(values)
 api=support.tools(a.hepta)
 meta=json.loads(before["native/process_params_composition.json"]);base=before["native/process_params.hepta"]
 assert SHA(base)==meta["source_sha256"] and len(base)==meta["source_bytes"]
 roots={name:meta["aliases"][name] for name in ("load","get","put","string_info","unit")}
 word=lambda x:int.from_bytes(x.encode(),"little")
 constants={"REQUEST":word("HPRVLQ01"),"RESPONSE":word("HPRVLR01"),"TYPED":word("HPRPAR01"),
 "HOST":word("HRCFTR01"),"INVALID":0xffffffff,"CAPACITY":0xfffffffe,"MAXIMUM":2**64-1,
 "FIELDS":4096,"LISTS":8192,"SCRATCH":65536,"DANGEROUS_COUNT":len(dangerous),"ENV_COUNT":len(env)}
 raw,aliases,proof=support.compile_new(api,base,roots,pseudo,constants,"runtime_process_validation")
 assert all(take(n)==b for n,b in before.items())
 q.mkdir()
 record={"schema":"hepta.runtime.process-validation.v1",**proof,"aliases":aliases,"constants":constants,
 "source_bytes":len(raw),"source_sha256":SHA(raw),"input_files":{n:{"bytes":len(b),"sha256":SHA(b)} for n,b in before.items()},
 "host_wire":"HRCFTR01","host_from_installed_owner_required":True,"native_compiled":False,"public_handler_qualified":False}
 (q/"process_validation.hepta").write_bytes(raw);(q/"process_validation_composition.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
 (q/"process_validation.pseudo").write_text(pseudo)
 assert all(take(n)==b for n,b in before.items())
 print(json.dumps({"bytes":len(raw),"sha256":SHA(raw),"functions":proof["functions"],"blocks":proof["blocks"],"operations":proof["operations"]}))
if __name__=="__main__":main()
