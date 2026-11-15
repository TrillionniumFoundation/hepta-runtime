import json,sys,pathlib,hashlib,os,subprocess
root=pathlib.Path(sys.argv[1])
payload=json.load(sys.stdin)
assert not root.exists(),str(root)
assert all('/' not in n and n not in ('.','..') for n in payload)
for n,v in payload.items():
 b=v['content'].encode();assert len(b)==v['bytes'];assert hashlib.sha256(b).hexdigest()==v['sha256']
os.umask(0o077);root.mkdir(mode=0o700)
for n,v in payload.items():
 p=root/n
 with p.open('xb') as f:
  f.write(v['content'].encode());f.flush();os.fsync(f.fileno())
 assert hashlib.sha256(p.read_bytes()).hexdigest()==v['sha256']
print(json.dumps({'phase':'installed_fresh_bundle','root':str(root),'files':{n:{'bytes':v['bytes'],'sha256':v['sha256']} for n,v in payload.items()}),flush=True)
if len(sys.argv)>2:
 raise SystemExit(subprocess.run(['/usr/bin/python3','-B',str(root/'install_measurement_tools.py'),'--bundle-sha256',sys.argv[2]]).returncode)
