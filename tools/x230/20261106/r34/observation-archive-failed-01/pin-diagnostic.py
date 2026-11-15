import ast,base64,datetime,hashlib,json,os,stat
from pathlib import Path
os.umask(0o077)
ROOT=Path('/home/qian/hepta-runtime-optimization-20261106-r34')
R16=Path('/home/qian/hepta-runtime-optimization-20261104-r16')
def need(v,m):
    if not v: raise RuntimeError(m)
def ident(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def read(path,pin=None,cap=8*1024*1024):
    need(path.is_absolute() and path.resolve(strict=True)==path,"indirect input")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as f:
        a=os.fstat(f.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=cap,"unsafe original")
        raw=f.read(a.st_size+1); b=os.fstat(f.fileno())
    c=path.lstat(); fields=("st_dev","st_ino","st_mode","st_uid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
    need(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(c,k) for k in fields),"original changed")
    if pin: need(ident(raw)=={k:pin[k] for k in ("bytes","sha256")},"original identity mismatch "+str(path))
    return raw
def create(path,raw):
    need(path.parent.resolve(strict=True)==path.parent,"indirect output")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    read(path,ident(raw))
    return {"path":str(path),**ident(raw)}
def native(term,receipt,job,state,code):
    need(term["job_id"]==receipt["job_id"]==job and term["state"]==state and term["exit_code"]==code,"original native outcome differs")
    need(all(term[k] is False for k in ("automatic_retry","cancelled","timed_out")) and all(term[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed")),"native incomplete")
    need(term["terminal_publication_protocol"]==1 and term["log_synced"]=={"stdout":True,"stderr":True} and term["log_errors"]=={"stdout":None,"stderr":None} and term["log_truncated"]=={"stdout":False,"stderr":False},"native storage differs")
    for k in ("stdout","stderr"):
        v=receipt[k]; raw=bytes.fromhex(v["bytes_hex"])
        need(v["offset"]==0 and v["eof"] is True and len(raw)==v["size"]==v["next_offset"]==term["log_bytes"][k]["stored"]==term["log_bytes"][k]["seen"] and raw==v["text"].encode(),"native stream incomplete")

script_path=ROOT/'archive_r34_observation.py'
source=read(script_path,{'bytes':59309,'sha256':'dfe08662dd65995a0e27edc6c06bf4e1754a1fc936a81c10657f2ff4e8c1695b'})
assignments={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(source).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('STATIC_PINS','ACTUAL')}
pins={**assignments['STATIC_PINS'],**assignments['ACTUAL']['sha256']}
need(len(assignments['STATIC_PINS'])==70 and len(assignments['ACTUAL']['sha256'])==29 and len(pins)==99,'unexpected pin inventory')
rows=[]
for name,expected in sorted(pins.items()):
 relative=Path(name);need(not relative.is_absolute() and '..' not in relative.parts,'unsafe input key')
 path=R16/name[len('external/r16/'):] if name.startswith('external/r16/') else ROOT/name
 raw=read(path);actual=ident(raw);rows.append({'name':name,'path':str(path),'expected_sha256':expected,**actual,'matches':actual['sha256']==expected,'kind':'static' if name in assignments['STATIC_PINS'] else 'actual'})
outputs={suffix:os.path.lexists(ROOT/('observation-evidence-01'+suffix)) for suffix in ('.tar.gz','.manifest.json','.compact.json')}
need(not any(outputs.values()),'original failed collector unexpectedly wrote archive output')
originals={}
for row in json.loads("[{\"name\":\"observation-archive-native-failed-01.json\",\"bytes\":724,\"sha256\":\"05e63545e78aac2ca96451fe6964daa6ad2d88c3bc6bc5912dc81e8bd8e922ad\",\"data_base64\":\"ewogICJhdF91bml4X21zIjogMTc5Mzk0MTg5MDA0MCwKICAiYXVkaXRfcmVjb3JkZWQiOiB0cnVlLAogICJhdXRvbWF0aWNfcmV0cnkiOiBmYWxzZSwKICAiY2FuY2VsbGVkIjogZmFsc2UsCiAgImV4aXRfY29kZSI6IDEsCiAgImpvYl9pZCI6ICIxYTFhZjQ0Y2QwMi1mYzA1LTY3MzkiLAogICJsYXVuY2hfbm9uY2UiOiAiMTBmYWRlNWRmOWQxMjYwYmM4M2FiYTAwOGMzMzExZDgiLAogICJsb2dfYnl0ZXMiOiB7CiAgICAic3RkZXJyIjogewogICAgICAic2VlbiI6IDQyLAogICAgICAic3RvcmVkIjogNDIKICAgIH0sCiAgICAic3Rkb3V0IjogewogICAgICAic2VlbiI6IDAsCiAgICAgICJzdG9yZWQiOiAwCiAgICB9CiAgfSwKICAibG9nX2Vycm9ycyI6IHsKICAgICJzdGRlcnIiOiBudWxsLAogICAgInN0ZG91dCI6IG51bGwKICB9LAogICJsb2dfc3luY2VkIjogewogICAgInN0ZGVyciI6IHRydWUsCiAgICAic3Rkb3V0IjogdHJ1ZQogIH0sCiAgImxvZ190cnVuY2F0ZWQiOiB7CiAgICAic3RkZXJyIjogZmFsc2UsCiAgICAic3Rkb3V0IjogZmFsc2UKICB9LAogICJvdXRwdXRfY29tcGxldGUiOiB0cnVlLAogICJvdXRwdXRfZHVyYWJsZSI6IHRydWUsCiAgInN0YXRlIjogImZhaWxlZCIsCiAgInRlcm1pbmFsX3B1YmxpY2F0aW9uX2NvbmZpcm1lZCI6IHRydWUsCiAgInRlcm1pbmFsX3B1YmxpY2F0aW9uX3Byb3RvY29sIjogMSwKICAidGltZWRfb3V0IjogZmFsc2UKfQ==\"},{\"name\":\"observation-archive-read-failed-01.json\",\"bytes\":446,\"sha256\":\"cd9042a81f3641250584347eafc4c166e8b010888edb3a6db2a62b3a21b4f0bf\",\"data_base64\":\"ewogICJhdWRpdF9yZWNvcmRlZCI6IHRydWUsCiAgImpvYl9pZCI6ICIxYTFhZjQ0Y2QwMi1mYzA1LTY3MzkiLAogICJzdGRlcnIiOiB7CiAgICAiYnl0ZXNfaGV4IjogIjU2NjE2Yzc1NjU0NTcyNzI2ZjcyM2EyMDY2NzI2ZjdhNjU2ZTIwNmY3MjY5Njc2OTZlNjE2YzIwNjk2ZTcwNzU3NDIwNjQ2OTY2NjY2NTcyNzMwYSIsCiAgICAiZW9mIjogdHJ1ZSwKICAgICJuZXh0X29mZnNldCI6IDQyLAogICAgIm9mZnNldCI6IDAsCiAgICAic2l6ZSI6IDQyLAogICAgInRleHQiOiAiVmFsdWVFcnJvcjogZnJvemVuIG9yaWdpbmFsIGlucHV0IGRpZmZlcnNcbiIKICB9LAogICJzdGRvdXQiOiB7CiAgICAiYnl0ZXNfaGV4IjogIiIsCiAgICAiZW9mIjogdHJ1ZSwKICAgICJuZXh0X29mZnNldCI6IDAsCiAgICAib2Zmc2V0IjogMCwKICAgICJzaXplIjogMCwKICAgICJ0ZXh0IjogIiIKICB9Cn0=\"}]"):
 raw=base64.b64decode(row['data_base64'],validate=True);need(ident(raw)=={k:row[k] for k in ('bytes','sha256')},'failure original differs');originals[row['name']]=create(ROOT/row['name'],raw)
report={'schema':'hepta-r34-observation-archive-pin-diagnostic/v1','captured_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'original_failed_archive_job_id':'1a1af44cd02-fc05-6739','collector':{'path':str(script_path),**ident(source)},'read_only_for_inputs':True,'collector_executed':False,'tests_or_benchmarks_or_auditors_executed':False,'original_archive_outputs_exist':outputs,'pins_checked':len(rows),'mismatches':[r for r in rows if not r['matches']],'all_rows':rows,'preserved_failure_originals':originals}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();receipt=create(ROOT/'observation-archive-pin-diagnostic-01.json',raw)
print(json.dumps({'receipt':receipt,'pins_checked':len(rows),'mismatches':report['mismatches'],'original_archive_outputs_exist':outputs}),flush=True)
