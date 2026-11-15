#!/usr/bin/env python3
import pathlib,os,stat,json,hashlib,datetime,sys
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r5-root-artifact-preservation"
D=pathlib.Path("/home/qian-qi/hepta-runtime-v10-root-pinned-native-757ef1-20261014-r1")
FP="498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c"
pins={"debug":"757ef140732744e4c29d50e615375d3bb300b6288c520d741bd6a3ed8f0813bd","release":"495789d343228be04a4ceebd8af7b5dc600bcbb114ef5a958b89da6db45cbc5c"}
stage=R/"deploy/stage_dc_successor.py"
assert hashlib.sha256(stage.read_bytes()).hexdigest()=="80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582"
sys.path.insert(0,str(stage.parent));import stage_dc_successor as S
before=S.source_identity(R);assert before["source_code_fingerprint"]==FP and len(before["source_files"])==98
assert not D.exists() and not Q.exists()
v=os.statvfs(R);assert v.f_bavail*v.f_frsize>=2*1024**3
D.mkdir(mode=0o700);Q.mkdir(mode=0o700);os.umask(0o077)
fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_uid","st_gid","st_mode","st_nlink")
def version(s):return {f:getattr(s,f) for f in fields}
rows=[]
for label,expected in pins.items():
 src=R/"target"/label/"hepta-runtime";dst=D/("hepta-runtime-"+label)
 fd=os.open(src,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and not a.st_mode&0o022
  out=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o700)
  h=hashlib.sha256();count=0
  try:
   while True:
    raw=os.read(fd,1048576)
    if not raw:break
    h.update(raw);count+=len(raw)
    at=0
    while at<len(raw):at+=os.write(out,raw[at:])
   os.fsync(out)
  finally:os.close(out)
  assert h.hexdigest()==expected and count==a.st_size
  assert version(a)==version(os.fstat(fd))==version(src.lstat())
 finally:os.close(fd)
 df=os.open(dst,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  b=os.fstat(df);h2=hashlib.sha256()
  while True:
   raw=os.read(df,1048576)
   if not raw:break
   h2.update(raw)
  assert h2.hexdigest()==expected and stat.S_IMODE(b.st_mode)==0o700 and b.st_nlink==1 and b.st_uid==os.getuid()
  assert version(b)==version(os.fstat(df))==version(dst.lstat())
 finally:os.close(df)
 rows.append({"label":label,"source":str(src),"preserved":str(dst),"sha256":expected,"bytes":count,"source_version":version(a),"preserved_version":version(b)})
df=os.open(D,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);os.fsync(df);os.close(df)
assert S.source_identity(R)==before
receipt={"schema":"hepta-v10-root-artifact-preservation-v1","recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source_fingerprint":FP,"source_inputs":98,"source_before_after_identical":True,"fresh_root_build_job":"1a137bf9b9b-b2f-bc9","artifacts":rows,"installation_or_full_replacement_qualified":False}
raw=(json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode()
for p in (D/"manifest.json",Q/"receipt.json"):
 f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:os.write(f,raw);os.fsync(f)
 finally:os.close(f)
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
print(json.dumps({"completed":True,"manifest_path":str(D/"manifest.json"),"manifest_sha256":hashlib.sha256(raw).hexdigest(),"artifacts":{x["label"]:x["preserved"] for x in rows}},sort_keys=True))
