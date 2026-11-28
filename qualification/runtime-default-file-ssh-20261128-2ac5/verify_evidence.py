#!/usr/bin/env python3
"""Verify all archived bytes without extracting or executing captured files."""
from pathlib import Path
import argparse,gzip,hashlib,json,tarfile,tempfile
def digest(raw):return hashlib.sha256(raw).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source-root',type=Path);a=ap.parse_args()
 root=Path(__file__).resolve().parent
 q=json.loads((root/'qualification.json').read_bytes());results=[]
 for domain,desc in q['evidence'].items():
  packed=(root/desc['manifest_file']).read_bytes()
  assert digest(packed)==desc['manifest_gzip_sha256']
  raw=gzip.decompress(packed);assert digest(raw)==desc['manifest_sha256']
  manifest=json.loads(raw);expected=manifest['objects'];seen=set();whole=hashlib.sha256()
  with tempfile.TemporaryFile()as combined:
   for part in desc['parts']:
    raw=(root/part['path']).read_bytes()
    assert len(raw)==part['bytes']and digest(raw)==part['sha256']
    whole.update(raw);combined.write(raw)
   assert whole.hexdigest()==desc['archive_sha256']
   combined.seek(0)
   with tarfile.open(fileobj=combined,mode='r:gz')as archive:
    for item in archive:
     assert item.isfile()and item.mode==0o400 and item.name.startswith('objects/')
     key=item.name.split('/')[1]
     assert len(item.name.split('/'))==2 and key in expected and key not in seen
     h=hashlib.sha256();count=0;f=archive.extractfile(item)
     for block in iter(lambda:f.read(1024*1024),b''):h.update(block);count+=len(block)
     assert count==item.size==expected[key]['bytes']and h.hexdigest()==key
     seen.add(key)
  assert seen==set(expected)
  files=[x for x in manifest['members']if x['kind']=='file']
  assert all(x['sha256']in seen and expected[x['sha256']]['bytes']==x['bytes']for x in files)
  results.append({'domain':domain,'objects':len(seen),'recorded_paths':len(manifest['members']),'files':len(files)})
 if a.source_root:
  for row in json.loads((root/'source-changes.json').read_bytes()):
   path=a.source_root/row['path'];raw=path.read_bytes()
   assert len(raw)==row['bytes']and digest(raw)==row['sha256'],row['path']
 print(json.dumps({'passed':True,'archives':results,'current_source_checked':a.source_root is not None},sort_keys=True))
if __name__=='__main__':main()
