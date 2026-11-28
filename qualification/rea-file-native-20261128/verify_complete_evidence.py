from pathlib import Path
import os,sys,json,subprocess,tarfile,hashlib,gzip,time,stat,shutil
os.umask(0o022);base=Path('/Users/qianqi/work/hia-runtime-rea-formats-20261128-2ac5');out=base/'rea-file-complete-evidence-integration-v1';out.mkdir(mode=0o700,exist_ok=False);(out/'driver.py').write_text(sys.argv[1]);start=time.monotonic();sha=lambda b:hashlib.sha256(b).hexdigest()
scopes=[
 ('desktop','desktop:/home/qian-qi/hia-runtime-rea-formats-20261128-2ac5/rea-file-complete-evidence-v1','da11a1bf29680b2e1c8eabe11304d7de1cb80b25d87a2838abf8756619bbf69a'),
 ('original','rog:/home/qian-qi/hia-runtime-rea-files-original-20261128-2ac5/rea-file-original-complete-evidence-v1','617c225441a19a131b3c16ff15b48f9a07d9a32d40b561755d4a2f11135cc5e0'),
 ('author',None,'e73647455535780d58ebee71ec9be2024c5361f86ead10a1e68eec289ef7ef4f')]
results={}
for label,remote,manifest_sha in scopes:
 destination=out/label
 if remote is None:shutil.copytree(base/'rea-file-author-complete-evidence-v1',destination,copy_function=shutil.copy2)
 else:
  p=subprocess.run(['/usr/bin/scp','-r',remote,str(destination)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
  (out/(label+'-transfer.stdout')).write_bytes(p.stdout);(out/(label+'-transfer.stderr')).write_bytes(p.stderr);assert p.returncode==0,(label,p.stderr)
 raw=(destination/'manifest.json').read_bytes();assert sha(raw)==manifest_sha
 m=json.loads(raw);terminal=json.loads((destination/'terminal.json').read_bytes());assert terminal['status']=='COMPLETE_EVIDENCE_CAPTURE_AND_FULL_READBACK_PASS'and terminal['manifest_sha256']==manifest_sha
 objects=out/(label+'-verified-objects');objects.mkdir(mode=0o700);seen=set()
 for shard in m['shards']:
  p=destination/shard['name'];packed=p.read_bytes();assert len(packed)==shard['bytes']and sha(packed)==shard['sha256']
  with tarfile.open(p,'r:gz')as archive:
   for member in archive:
    assert member.isfile()and member.name.startswith('objects/')
    digest=member.name.split('/')[1];data=archive.extractfile(member).read()
    assert digest not in seen and digest==sha(data)and len(data)==m['objects'][digest]['bytes']and m['objects'][digest]['shard']==shard['name']
    q=objects/digest
    with q.open('xb')as stream:stream.write(data)
    q.chmod(0o400);seen.add(digest)
 assert seen==set(m['objects'])
 for name,row in m['files'].items():
  digest=hashlib.sha256();extent=0
  for part in row['chunks']:
   data=(objects/part).read_bytes();digest.update(data);extent+=len(data)
  assert digest.hexdigest()==row['sha256']and extent==row['bytes'],(label,name)
 compressed=gzip.compress(raw,compresslevel=6,mtime=0);(destination/'manifest.json.gz').write_bytes(compressed)
 assert gzip.decompress(compressed)==raw
 results[label]={'logical_files':len(m['files']),'logical_bytes':sum(r['bytes']for r in m['files'].values()),'directories':len(m['directories']),'special_entries':len(m['special_entries']),'unique_chunks':len(seen),'manifest_sha256':manifest_sha,'manifest_bytes':len(raw),'compressed_manifest_bytes':len(compressed),'compressed_manifest_sha256':sha(compressed),'shards':m['shards'],'original_all_bytes_and_modes_preserved':True,'all_chunk_and_logical_file_bytes_reverified':True}
 (out/'verification-progress.json').write_text(json.dumps(results,sort_keys=True,indent=2)+'\n');print(json.dumps({'scope':label,'files':len(m['files']),'objects':len(seen),'status':'FULL_BYTES_VERIFIED'}),flush=True)
report={'status':'ALL_REA_FILE_COMPONENT_ORIGINAL_AND_AUTHOR_EVIDENCE_INDEPENDENTLY_VERIFIED','scopes':results,'seconds':time.monotonic()-start}
(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True),flush=True)
