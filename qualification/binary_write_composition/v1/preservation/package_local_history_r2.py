"""Verify the retained long-path archive, then deduplicate identical source blocks."""
from pathlib import Path
import gzip,hashlib,io,json,stat,tarfile,time
ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/'development'
OUT=ROOT/'publication/qualification/binary_write_composition/v1/local-history'
def sha(b):return hashlib.sha256(b).hexdigest()
def encoded(v):return(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def main():
 began=time.monotonic();original_raw=(OUT/'MANIFEST.json').read_bytes();old=json.loads(original_raw);rows=old['files']
 legacy=ROOT/'local-history.tar.gz';seen=[];pax=0
 with legacy.open('rb') as stream:legacy_sha=hashlib.file_digest(stream,'sha256').hexdigest()
 assert legacy_sha=='ef939dae4120b31654850ead47cbaf5def3cbfb1ac3272a9edfbdccaf191cc18'
 with tarfile.open(legacy,'r|gz') as tar:
  for member in tar:
   assert member.isfile() and member.uid==member.gid==member.mtime==0
   assert member.pax_headers==({'path':member.name} if len(member.name.encode('ascii'))>100 else {})
   pax+=bool(member.pax_headers);raw=tar.extractfile(member).read()
   if not seen:assert member.name=='MANIFEST.json' and raw==original_raw
   else:
    name=member.name.removeprefix('development/');assert member.name=='development/'+name
    assert dict(bytes=len(raw),sha256=sha(raw),mode=member.mode)==rows[name]
   seen.append(member.name);tar.members.clear()
 assert pax==68 and seen==['MANIFEST.json']+['development/'+n for n in rows]
 files={};objects={};locations={}
 for name,row in rows.items():
  p=SOURCE/name;assert stat.S_ISREG(p.lstat().st_mode) and not p.is_symlink()
  before=p.stat();whole=hashlib.sha256();chunks=[];offset=0
  with p.open('rb') as stream:
   while raw:=stream.read(1<<20):
    key=sha(raw);objects.setdefault(key,len(raw));assert objects[key]==len(raw)
    locations.setdefault(key,(p,offset));chunks.append(key);offset+=len(raw);whole.update(raw)
  assert dict(bytes=offset,sha256=whole.hexdigest(),mode=stat.S_IMODE(before.st_mode))==row
  assert p.stat()==before
  files[name]={**row,'chunks':chunks}
 manifest=dict(schema='hepta.runtime.binary-write-composition.local-development-cas.v1',files=files,objects=dict(sorted(objects.items())),
  original_manifest_sha256=sha(original_raw),verified_original_archive_sha256=legacy_sha,exact_pax_path_records=68,
  runtime_product_executions_added=0,new_qualification_claimed=False,old_holds_preserved=True)
 raw=encoded(manifest);assert not(OUT/'CAS_MANIFEST.json').exists();(OUT/'CAS_MANIFEST.json').write_bytes(raw)
 archive=ROOT/'local-history-cas.tar.gz';assert not archive.exists()
 with archive.open('xb') as target,gzip.GzipFile(filename='',fileobj=target,mode='wb',mtime=0,compresslevel=1) as compressed,tarfile.open(fileobj=compressed,mode='w|') as tar:
  info=tarfile.TarInfo('CAS_MANIFEST.json');info.size=len(raw);info.mode=0o644;tar.addfile(info,io.BytesIO(raw))
  for key,size in sorted(objects.items()):
   p,offset=locations[key]
   with p.open('rb') as stream:stream.seek(offset);b=stream.read(size)
   assert len(b)==size and sha(b)==key
   info=tarfile.TarInfo('objects/'+key);info.size=size;info.mode=0o644;tar.addfile(info,io.BytesIO(b))
 seen=[]
 with tarfile.open(archive,'r|gz') as tar:
  for member in tar:
   assert member.isfile() and member.uid==member.gid==member.mtime==0 and member.mode==0o644 and not member.pax_headers
   value=tar.extractfile(member).read()
   if not seen:assert member.name=='CAS_MANIFEST.json' and value==raw
   else:assert member.name.startswith('objects/') and objects[member.name[8:]]==len(value) and sha(value)==member.name[8:]
   seen.append(member.name);tar.members.clear()
 assert seen==['CAS_MANIFEST.json']+['objects/'+n for n in sorted(objects)]
 for name,row in rows.items():
  p=SOURCE/name;b=p.read_bytes();assert dict(bytes=len(b),sha256=sha(b),mode=stat.S_IMODE(p.stat().st_mode))==row
 parts=[];full=hashlib.sha256();size=0
 with archive.open('rb') as stream:
  while value:=stream.read(9<<20):
   name='development.tar.gz.part'+str(len(parts)+1).zfill(3);(OUT/name).write_bytes(value)
   parts.append(dict(path=name,offset=size,bytes=len(value),sha256=sha(value)));size+=len(value);full.update(value)
 result=dict(schema='hepta.runtime.binary-write-composition.local-development-cas-parts.v1',status='LOCAL_HISTORY_ARCHIVE_BYTES_PASS',
  archive_bytes=size,archive_sha256=full.hexdigest(),manifest_sha256=sha(raw),files=len(rows),logical_bytes=sum(x['bytes'] for x in rows.values()),
  unique_bytes=sum(objects.values()),objects=len(objects),parts=parts,elapsed_seconds=time.monotonic()-began,
  original_long_path_archive_fully_read=True,source_bytes_verified_before_and_after=True,whole_archive_read=True,
  runtime_product_executions_added=0,new_qualification_claimed=False,old_holds_preserved=True)
 (OUT/'EVIDENCE.json').write_bytes(encoded(result));print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
