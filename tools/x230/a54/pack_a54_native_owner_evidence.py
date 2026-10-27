import os,sys,json,gzip,hashlib,pathlib,stat,base64
B=pathlib.Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
root=B/'a54-native-owner-remote-r01'
def stamp(s):
 return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p):
 s=p.lstat()
 assert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid(),str(p)
 b=p.read_bytes();assert len(b)==s.st_size and stamp(s)==stamp(p.lstat());return b
def sha(b):return hashlib.sha256(b).hexdigest()
raw=read(root/'report.json');assert sha(raw)=='1f3ee6c71d3e668b6af36d053b38ea2d007e21d0ddc4143660b1450977c02d72'
report=json.loads(raw)
assert report['passed'] and not report['errors'] and report['frozen_inputs_unchanged'] and not report['unexecuted_cases']
assert [x['name'] for x in report['cases']]==['controller-loss','reply-loss','owner-loss']
summary={'schema':'hepta-a54-native-owner-recovery-summary/v1','passed':True,'report_sha256':sha(raw),'report_bytes':len(raw),'plan_sha256':report['plan_sha256'],'qualified_release':report['qualified_bundle']['binary']['sha256'],'cases':[]}
for r in report['cases']:
 assert r['passed'] and r['business_effect_count']==1 and r['same_job_identity_preserved']
 summary['cases'].append({'name':r['name'],'passed':r['passed'],'original_job_id':r['original_record']['id'],'business_effect_count':r['business_effect_count'],'first_recovered_status':r['first_recovered_status'],'same_key_reused':r['same_key_reuse']['reused'],'same_key_retried_launch':r['same_key_reuse']['retried_launch'],'shutdown':r['shutdown'],'custody_ssh_shutdown':r['custody_ssh_shutdown'],'remote_cleanup_complete':r['remote_finish']['report']['cleanup_complete']})
files={}
total=0
for p in sorted(root.rglob('*')):
 assert not p.is_symlink()
 if p.is_file():
  b=read(p);assert len(b)<16*1024*1024
  total+=len(b);assert total<64*1024*1024
  files[str(p.relative_to(root))]={'link_count':p.lstat().st_nlink,'bytes':len(b),'sha256':sha(b),'base64':base64.b64encode(b).decode()}
assert len(files)==88,'expected fixed complete 88-file evidence'
bundle={'schema':'hepta-a54-native-owner-evidence-bundle/v1','root':str(root),'report_sha256':sha(raw),'files':files}
encoded=json.dumps(bundle,sort_keys=True,separators=(',',':')).encode()+b'\n'
packed=gzip.compress(encoded,mtime=0)
def create(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
out=B/'a54-native-owner-remote-r01.evidence.json.gz'
create(out,packed)
summary['evidence']={'path':str(out),'files':len(files),'source_bytes':total,'bytes':len(packed),'sha256':sha(packed),'expanded_sha256':sha(encoded)}
sraw=json.dumps(summary,sort_keys=True,indent=2).encode()+b'\n'
sp=B/'a54-native-owner-remote-r01.summary.json';create(sp,sraw)
fd=os.open(B,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'passed':True,'cases':len(summary['cases']),'summary':{'path':str(sp),'bytes':len(sraw),'sha256':sha(sraw)},'evidence':summary['evidence']}),flush=True)
