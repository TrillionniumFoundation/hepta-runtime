"""Prepare and validate one new private-composition tree; do not commit or push."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,shutil,signal,stat,subprocess,tarfile,time
BASE='acd4d7aa766e8f74a7cfbd26b0d58f68cd5e5b39'
TREE='aaa67939fa68736dc63318a1bb8304330f05a8bc'
PREFIX='qualification/binary_write_composition/v1/'
PYTHON=['/usr/bin/python3.12','-I','-S','-B']
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(p):
 with p.open('rb') as s:return dict(bytes=p.stat().st_size,sha256=hashlib.file_digest(s,'sha256').hexdigest())
def gone(pgid):
 try:os.killpg(pgid,0);return False
 except ProcessLookupError:return True
def run(root,name,argv,limit):
 start=time.monotonic();folder=root/name;folder.mkdir();record=dict(name=name,argv=argv,limit_seconds=limit,cleanup_seconds=5)
 with(folder/'stdout.log').open('xb')as out,(folder/'stderr.log').open('xb')as err:
  p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
  record.update(pid=p.pid,pgid=os.getpgid(p.pid),timeout=False)
  (folder/'START.json').write_bytes(encoded(record));print(json.dumps({'stage':name,'pid':p.pid}),flush=True)
  try:record['returncode']=p.wait(timeout=limit)
  except subprocess.TimeoutExpired:
   record['timeout']=True;os.killpg(p.pid,signal.SIGTERM)
   try:record['returncode']=p.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);record['returncode']=p.wait(timeout=5)
 record.update(elapsed_seconds=time.monotonic()-start,whole_group_gone=gone(record['pgid']),stdout=pin(folder/'stdout.log'),stderr=pin(folder/'stderr.log'))
 (folder/'PROCESS.json').write_bytes(encoded(record));print(json.dumps(record,sort_keys=True),flush=True)
 assert record['returncode']==0 and not record['timeout'] and record['whole_group_gone']
 return record
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in('checkout','bundle','validation-root','original-build-package','original-qualified-root'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--bundle-sha256',required=True);a=p.parse_args();checkout=a.checkout.resolve(strict=True)
 assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD']).decode().strip()==BASE
 assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD^{tree}']).decode().strip()==TREE
 assert subprocess.check_output(['git','-C',str(checkout),'ls-tree','HEAD','qualification/binary_write_composition'])==b''
 assert pin(a.bundle)['sha256']==a.bundle_sha256
 assert not a.validation_root.exists();a.validation_root.mkdir();validation=a.validation_root.resolve()
 published=checkout/PREFIX;assert not published.exists()
 seen=[];manifest=None
 with tarfile.open(a.bundle,'r|gz')as tar:
  for member in tar:
   assert member.isfile() and member.mode==0o644 and member.uid==member.gid==member.mtime==0 and not member.pax_headers
   raw=tar.extractfile(member).read()
   if not seen:
    assert member.name=='BUNDLE_MANIFEST.json';manifest=json.loads(raw)
    assert manifest['base_commit']==BASE and manifest['base_tree']==TREE
    (validation/'BUNDLE_MANIFEST.json').write_bytes(raw)
   else:
    relative=PurePosixPath(member.name)
    assert relative.as_posix()==member.name and not relative.is_absolute() and '..'not in relative.parts and member.name.startswith(PREFIX)
    row=manifest['files'][member.name]
    assert dict(bytes=len(raw),sha256=sha(raw),mode=0o644)==row
    target=checkout/relative;target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('xb')as out:out.write(raw)
    target.chmod(0o644)
   seen.append(member.name);tar.members.clear()
 assert seen==['BUNDLE_MANIFEST.json']+list(manifest['files'])
 index=(published/'EVIDENCE.json').read_bytes();assert sha(index)=='4610829232660e22c0e58c698ac7fba16f4a2d7c942156400175a3aa23e6d161'
 assert index==(a.original_build_package/'EVIDENCE.json').read_bytes()
 evidence=json.loads(index);parts=json.loads((published/'PARTS.json').read_bytes())
 archive=a.original_build_package/'evidence.tar.gz';assert pin(archive)==dict(bytes=evidence['archive_bytes'],sha256=evidence['archive_sha256'])
 full=hashlib.sha256();count=0
 with archive.open('rb')as stream:
  for row,original in zip(parts['parts'],evidence['parts']):
   assert {k:v for k,v in row.items()if k!='path'}==original and row['offset']==count
   assert '/'not in row['path'] and row['path'].startswith('evidence.tar.gz.part')
   raw=stream.read(row['bytes']);assert len(raw)==row['bytes'] and sha(raw)==row['sha256']
   target=published/row['path'];assert not target.exists();target.write_bytes(raw);target.chmod(0o644)
   full.update(raw);count+=len(raw)
  assert stream.read(1)==b''
 assert count==evidence['archive_bytes'] and full.hexdigest()==evidence['archive_sha256']
 source=published/'source';original=a.original_qualified_root/'source'
 assert (source/'SOURCE_MANIFEST.json').read_bytes()==(original/'SOURCE_MANIFEST.json').read_bytes()
 for row in json.loads((source/'SOURCE_MANIFEST.json').read_bytes())['files']:
  assert (source/row['path']).read_bytes()==(original/row['path']).read_bytes()
 stages=[]
 stages.append(run(validation,'restore-build',PYTHON+[str(published/'restore_capture.py'),'--index',str(published/'EVIDENCE.json'),
  '--index-sha256',sha(index),'--parts',str(published/'PARTS.json'),'--output',str(validation/'restored-build')],180))
 stages.append(run(validation,'publication-readback',PYTHON+[str(published/'read_publication.py'),'--restored',str(validation/'restored-build/restored')],180))
 stages.append(run(validation,'restore-local-history',PYTHON+[str(published/'restore_local_history.py'),'--parts',str(published/'local-history'),
  '--output',str(validation/'restored-local-history')],180))
 shutil.copyfile(validation/'restored-build/RESTORED.json',published/'records/RESTORED_BUILD_BYTES.json')
 shutil.copyfile(validation/'publication-readback/stdout.log',published/'records/PUBLICATION_READBACK.json')
 shutil.copyfile(validation/'restored-local-history/RESTORED.json',published/'records/RESTORED_LOCAL_HISTORY_BYTES.json')
 files={}
 for path in sorted(published.rglob('*')):
  if not path.is_file():continue
  assert not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
  path.chmod(0o644);raw=path.read_bytes();name=path.relative_to(checkout).as_posix()
  files[name]=dict(bytes=len(raw),sha256=sha(raw),mode='100644',type='blob',git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
 record=dict(status='PREPARED_EXACT_PUBLICATION_AND_ALL_RESTORED_BYTES_PASS',base_commit=BASE,base_tree=TREE,
  bundle=pin(a.bundle),files=files,stages=stages,new_files=len(files),new_bytes=sum(x['bytes']for x in files.values()),
  product_executions_added=0,semantic_qualification_repeated=False,public_binary_write_registered=False,whole_runtime_replaced=False)
 (validation/'PREPARED.json').write_bytes(encoded(record))
 print(json.dumps({k:v for k,v in record.items()if k not in('files','stages')},sort_keys=True),flush=True)
if __name__=='__main__':main()
