#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,tarfile,tempfile,stat,sys
ROOT=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def verify():
 index=json.loads((ROOT/'evidence/index.json').read_bytes())
 count=logical=0
 for label,item in index.items():
  with tempfile.TemporaryFile()as f:
   digest=hashlib.sha256();size=0
   for row in item['parts']:
    b=(ROOT/'evidence'/row['path']).read_bytes()
    assert len(b)==row['bytes']and sha(b)==row['sha256'],row['path']
    digest.update(b);size+=len(b);f.write(b)
   assert size==item['bytes']and digest.hexdigest()==item['sha256'],label
   rows=json.loads((ROOT/'evidence'/item['manifest']).read_bytes())
   f.seek(0)
   with tarfile.open(fileobj=f,mode='r:gz')as tf:
    members=tf.getmembers();assert len(members)==len(rows)
    assert len(set(m.name for m in members))==len(rows)
    for m in members:
     x=rows[m.name];assert m.mode==x['mode']
     if x.get('type')=='symlink':
      assert m.issym()and m.linkname==x['target']
     else:
      assert m.isfile()
      b=tf.extractfile(m).read();assert len(b)==x['bytes']and sha(b)==x['sha256'],m.name
      logical+=len(b)
     count+=1
 print(json.dumps({'passed':True,'archives':len(index),'members':count,'logical_bytes':logical,'scope':'complete archived byte/mode readback only'}))
if __name__=='__main__':verify()
