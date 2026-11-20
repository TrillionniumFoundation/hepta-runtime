"""Retain every local development source, failed build and actual smoke record."""
from pathlib import Path
import gzip,hashlib,io,json,os,stat,tarfile,time
ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/'development'
OUT=ROOT/'publication/qualification/binary_write_composition/v1/local-history'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def ident(p):
 s=p.lstat();return(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def files():
 result={}
 for h,ds,fs in os.walk(SOURCE,followlinks=False):
  ds[:]=sorted(n for n in ds if n not in('.git','__pycache__'))
  for n in sorted(fs):
   if n.endswith('.pyc'):continue
   p=Path(h)/n;assert stat.S_ISREG(p.lstat().st_mode) and not p.is_symlink()
   result[p.relative_to(SOURCE).as_posix()]=p
 return dict(sorted(result.items()))
def main():
 assert not OUT.exists();OUT.mkdir()
 began=time.monotonic();paths=files();rows={};before={}
 for name,path in paths.items():
  before[name]=ident(path);raw=path.read_bytes();rows[name]=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(path.stat().st_mode));assert ident(path)==before[name]
 manifest=dict(schema='hepta.runtime.binary-write-composition.local-development.v1',recorded_origin=str(SOURCE),files=rows,
  runtime_product_executions_added=0,new_qualification_claimed=False,old_holds_preserved=True)
 raw=encoded(manifest);(OUT/'MANIFEST.json').write_bytes(raw)
 archive=ROOT/'local-history.tar.gz'
 assert not archive.exists()
 with archive.open('xb') as target,gzip.GzipFile(filename='',fileobj=target,mode='wb',mtime=0,compresslevel=1) as compressed,tarfile.open(fileobj=compressed,mode='w|') as tar:
  entry=tarfile.TarInfo('MANIFEST.json');entry.size=len(raw);entry.mode=0o644;tar.addfile(entry,io.BytesIO(raw))
  for name,path in paths.items():
   value=path.read_bytes();assert len(value)==rows[name]['bytes'] and sha(value)==rows[name]['sha256']
   entry=tarfile.TarInfo('development/'+name);entry.size=len(value);entry.mode=rows[name]['mode'];tar.addfile(entry,io.BytesIO(value))
 assert files()==paths
 for name,path in paths.items():assert ident(path)==before[name]
 seen=[]
 with tarfile.open(archive,'r|gz') as tar:
  for member in tar:
   assert member.isfile() and member.uid==member.gid==member.mtime==0 and not member.pax_headers
   value=tar.extractfile(member).read()
   if not seen:assert member.name=='MANIFEST.json' and value==raw
   else:
    name=member.name.removeprefix('development/');assert member.name=='development/'+name
    assert dict(bytes=len(value),sha256=sha(value),mode=member.mode)==rows[name]
   seen.append(member.name);tar.members.clear()
 assert seen==['MANIFEST.json']+['development/'+n for n in rows]
 parts=[];full=hashlib.sha256();size=0
 with archive.open('rb') as stream:
  while value:=stream.read(9<<20):
   name='development.tar.gz.part'+str(len(parts)+1).zfill(3)
   (OUT/name).write_bytes(value);parts.append(dict(path=name,offset=size,bytes=len(value),sha256=sha(value)))
   size+=len(value);full.update(value)
 result=dict(schema='hepta.runtime.binary-write-composition.local-development-parts.v1',status='LOCAL_HISTORY_ARCHIVE_BYTES_PASS',
  archive_bytes=size,archive_sha256=full.hexdigest(),manifest_sha256=sha(raw),files=len(rows),logical_bytes=sum(x['bytes'] for x in rows.values()),parts=parts,
  elapsed_seconds=time.monotonic()-began,source_bytes_verified_before_and_after=True,whole_archive_read=True,
  runtime_product_executions_added=0,new_qualification_claimed=False,old_holds_preserved=True)
 (OUT/'EVIDENCE.json').write_bytes(encoded(result));print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
