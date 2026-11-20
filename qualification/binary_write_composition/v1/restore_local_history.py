"""Restore the complete pinned local development history; execute no product."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,tarfile,time
INDEX='6b69ab9aff420e9b3d9f516506ced90761cc07e0f665e5d20e276f70b9d09308'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--parts',type=Path,default=Path(__file__).resolve().parent/'local-history')
 p.add_argument('--output',type=Path,required=True);a=p.parse_args();began=time.monotonic()
 raw_index=(a.parts/'EVIDENCE.json').read_bytes();assert sha(raw_index)==INDEX
 index=json.loads(raw_index);assert index['schema']=='hepta.runtime.binary-write-composition.local-development-cas-parts.v1'
 assert not a.output.exists() and not a.output.is_symlink();a.output.mkdir(parents=True)
 archive=a.output/'assembled.tar.gz';full=hashlib.sha256();size=0
 with archive.open('xb') as target:
  for number,row in enumerate(index['parts'],1):
   assert row['path']=='development.tar.gz.part'+str(number).zfill(3) and row['offset']==size
   path=a.parts/row['path'];assert path.is_file() and not path.is_symlink();raw=path.read_bytes()
   assert len(raw)==row['bytes'] and sha(raw)==row['sha256'];target.write(raw);size+=len(raw);full.update(raw)
 assert size==index['archive_bytes'] and full.hexdigest()==index['archive_sha256']
 objects=a.output/'objects';objects.mkdir();seen=[];manifest=None
 with tarfile.open(archive,'r|gz') as tar:
  for member in tar:
   assert member.isfile() and member.mode==0o644 and member.uid==member.gid==member.mtime==0 and not member.pax_headers
   raw=tar.extractfile(member).read()
   if not seen:
    assert member.name=='CAS_MANIFEST.json' and sha(raw)==index['manifest_sha256']
    assert raw==(a.parts/'CAS_MANIFEST.json').read_bytes();manifest=json.loads(raw)
    assert manifest['schema']=='hepta.runtime.binary-write-composition.local-development-cas.v1'
    (a.output/'CAS_MANIFEST.json').write_bytes(raw)
   else:
    assert member.name.startswith('objects/');key=member.name[8:]
    assert len(key)==64 and all(c in '0123456789abcdef'for c in key)
    assert sha(raw)==key and manifest['objects'][key]==len(raw) and 0<len(raw)<=1<<20
    with(objects/key).open('xb') as target:target.write(raw)
   seen.append(member.name);tar.members.clear()
 assert seen==['CAS_MANIFEST.json']+['objects/'+key for key in sorted(manifest['objects'])]
 root=a.output/'restored';root.mkdir();used=set();total=0
 for name,row in manifest['files'].items():
  relative=PurePosixPath(name)
  assert relative.as_posix()==name and not relative.is_absolute() and '..'not in relative.parts and '\\'not in name
  assert type(row['mode'])is int and 0<=row['mode']<=0o777
  target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);whole=hashlib.sha256();count=0
  with target.open('xb') as output:
   for key in row['chunks']:
    raw=(objects/key).read_bytes();assert sha(raw)==key and len(raw)==manifest['objects'][key]
    output.write(raw);whole.update(raw);count+=len(raw);used.add(key)
  target.chmod(row['mode']);assert count==row['bytes'] and whole.hexdigest()==row['sha256']
  assert sha(target.read_bytes())==row['sha256'] and target.stat().st_mode&0o777==row['mode'];total+=count
 assert used==set(manifest['objects']) and len(manifest['files'])==index['files']==3092 and total==index['logical_bytes']==310710677
 result=dict(status='PASS_ALL_LOCAL_DEVELOPMENT_BYTES_AND_MODES_RESTORED',files=3092,logical_bytes=total,
  archive_sha256=index['archive_sha256'],elapsed_seconds=time.monotonic()-began,source_and_failure_records_preserved=True,
  semantic_qualification_repeated=False,product_executions_added=0,public_binary_write_registered=False,whole_runtime_replaced=False)
 (a.output/'RESTORED.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
