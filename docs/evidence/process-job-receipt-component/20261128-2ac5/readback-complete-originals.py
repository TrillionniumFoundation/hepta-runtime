from pathlib import Path
import hashlib,json,subprocess,time
B=Path('/Users/qianqi/work/hia-runtime-process-owner-20261128-2ac5')
Q=B/'job-receipt-complete-readback-v1';Q.mkdir(mode=0o700)
args=['/usr/bin/scp','-oBatchMode=yes','-oStrictHostKeyChecking=yes','desktop:/home/qian-qi/hia-runtime-process-owner-20261128-2ac5/job-receipt-complete-archive-v1/originals.tar.gz',str(Q/'originals.tar.gz')]
start=time.monotonic();p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
(Q/'scp.stdout').write_bytes(p.stdout);(Q/'scp.stderr').write_bytes(p.stderr)
(Q/'scp.command.json').write_text(json.dumps({'argv':args,'returncode':p.returncode,'elapsed_seconds':time.monotonic()-start},indent=2)+'\n')
assert p.returncode==0,p.stderr.decode(errors='replace')
a=(Q/'originals.tar.gz').read_bytes();assert len(a)==3240124 and hashlib.sha256(a).hexdigest()=='085fa4a1ad6681a3471554ae956fdde9b4941e4fffe0cebbf0a6951cd5853446'
import tarfile
with tarfile.open(Q/'originals.tar.gz','r:gz') as tf:
 members=tf.getmembers();assert len({m.name for m in members})==len(members)
 raw=tf.extractfile('index.json').read()
 assert len(raw)==68765 and hashlib.sha256(raw).hexdigest()=='3337dfc2361f4d392c2dd93812edf7fc9faac3055a6a67582ab17a7c0eb843cc'
 index=json.loads(raw);expected={x['path']:x for x in index['rows']}
 assert set(m.name for m in members)==set(expected)|{'index.json'}
 for m in members:
  if m.name=='index.json':continue
  row=expected[m.name];assert m.mode==row['mode']
  if row['kind']=='directory':assert m.isdir()
  else:
   assert m.isfile() and not m.islnk() and not m.issym()
   raw=tf.extractfile(m).read();assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 receipt={'archive_bytes':len(a),'archive_sha256':hashlib.sha256(a).hexdigest(),'files':sum(x['kind']=='file' for x in index['rows']),'directories':sum(x['kind']=='directory' for x in index['rows']),'raw_bytes':sum(x.get('bytes',0) for x in index['rows']),'all_members_bytes_mode_verified':True,'no_original_removed':True}
 (Q/'index.json').write_text(json.dumps(index,sort_keys=True,indent=2)+'\n')
 (Q/'readback.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps(receipt),flush=True)
