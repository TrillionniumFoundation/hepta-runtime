#!/usr/bin/env python3
import pathlib,os,stat,hashlib,json,subprocess,types,sys,datetime,re
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
A=pathlib.Path("/home/qian-qi/hepta-runtime-operation-v10-20261013/docs/qualification/dc-functional-v10-operation-candidate-20261013/root-workflow-v10-controlled-draft-r1")
Q=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r8-reviewed-workflow"
W=R/".github/workflows/operator-parity.yml"
OLD="041c50bfffc323d4e0212afa077d080fdcf92f732d210bfc901cd81a59585fd2";NEW="b95310d5229ea63d8242f4fc121347020c2536bec0ac26c8d2edd222a3014000"
PINS={"operator-parity.before.yml":OLD,"operator-parity.v10.draft.yml":NEW,"operator-parity.v10.controlled.patch":"90b9ce58e24101eddd969159fca20ebe4c9dc1286a1342aa2e8a52aca01f582a","manifest.json":"267eab4ab368b4fc5b704b6e727953d30971baf01bd47641c941ef214042af9d"}
def read(p,pin):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and a.st_nlink==1 and not a.st_mode&0o022 and a.st_size<=1048576
  raw=os.read(fd,a.st_size+1);assert len(raw)==a.st_size and not os.read(fd,1)
  fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_uid","st_gid","st_mode","st_nlink")
  assert all(getattr(a,f)==getattr(os.fstat(fd),f)==getattr(pathlib.Path(p).lstat(),f) for f in fields)
  assert hashlib.sha256(raw).hexdigest()==pin
  return raw
 finally:os.close(fd)
stage=R/"deploy/stage_dc_successor.py";raw=read(stage,"80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582")
sys.path.insert(0,str(stage.parent));S=types.ModuleType("root_workflow_stage");S.__file__=str(stage);sys.modules[S.__name__]=S;exec(compile(raw,str(stage),"exec"),S.__dict__)
before=S.source_identity(R);assert before["source_code_fingerprint"]=="498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c" and len(before["source_files"])==98
assert read(W,OLD)==read(A/"operator-parity.before.yml",OLD)
payload={n:read(A/n,pin) for n,pin in PINS.items()}
patch=payload["operator-parity.v10.controlled.patch"]
assert re.findall(rb"^(?:---|\\+\\+\\+) ([^\\n]+)",patch,re.M)==[b"a/.github/workflows/operator-parity.yml",b"b/.github/workflows/operator-parity.yml"]
old=payload["operator-parity.before.yml"].decode();new=payload["operator-parity.v10.draft.yml"].decode()
def block(t,tag):
 at=t.index("sha256sum --check <<'"+tag+"'")
 end=t.index("          "+tag,at)+len("          "+tag)
 return t[at:end]
assert block(old,"HEPTA_REVIEWED_V9_INPUTS")==block(new,"HEPTA_REVIEWED_V9_INPUTS")
for suffix in ("signal_fixture","health_multiread"):
 rows=[x for x in old.splitlines() if "python3 -B tests/dc_functional_v9_"+suffix+"_safety_tests.py" in x]
 assert len(rows)==1 and rows[0] in new.splitlines()
assert not Q.exists();Q.mkdir(mode=0o700);os.umask(0o077)
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
for n,raw in payload.items():(Q/n).write_bytes(raw)
commands=[];lines=new.splitlines();i=0
while i<len(lines):
 if lines[i].strip()=="run: |":
  i+=1;body=[]
  while i<len(lines) and (not lines[i].strip() or lines[i].startswith("          ")):
   body.append(lines[i][10:] if lines[i].startswith("          ") else "");i+=1
  commands.append("\n".join(body)+"\n")
 else:i+=1
assert len(commands)==4
checks=[]
for i,cmd in enumerate(commands):
 cmd=cmd.replace("${{ github.sha }}","a"*40)
 p=subprocess.run(["/bin/bash","-n"],input=cmd,text=True,capture_output=True)
 (Q/("shell-"+str(i)+".sh")).write_text(cmd);(Q/("shell-"+str(i)+".stderr.log")).write_text(p.stderr)
 checks.append({"block":i,"shell_syntax_exit":p.returncode});assert p.returncode==0
for phase,args in (("check",["git","apply","--check",str(Q/"operator-parity.v10.controlled.patch")]),("apply",["git","apply",str(Q/"operator-parity.v10.controlled.patch")])):
 p=subprocess.run(args,cwd=R,capture_output=True,text=True);(Q/("git-"+phase+".stdout.log")).write_text(p.stdout);(Q/("git-"+phase+".stderr.log")).write_text(p.stderr);assert p.returncode==0
assert read(W,NEW)==payload["operator-parity.v10.draft.yml"]
after=S.source_identity(R);assert after==before
receipt={"schema":"hepta-v10-root-reviewed-workflow-integration-v1","completed":True,"recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"old_sha256":OLD,"new_sha256":NEW,"controlled_patch_sha256":PINS["operator-parity.v10.controlled.patch"],"only_workflow_mutated":True,"full_compile_input_identity_unchanged":True,"source_fingerprint":before["source_code_fingerprint"],"source_inputs":98,"old_v9_pin_block_and_18_plus_24_offline_commands_byte_exact":True,"shell_checks":checks,"hosted_CI_claim":False,"full_DC_replacement_qualified":False}
(Q/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps(receipt,sort_keys=True))
