from pathlib import Path,PurePosixPath
import zipfile,tarfile,gzip,io,json,hashlib,base64,re
root=Path('/mnt/data/rea-source-originals');ref=Path('/mnt/data/source-more-originals/rea-6-8-0-oracle-418-reference.zip');out=Path('/mnt/data/source-only-recovery-20261103');out.mkdir(exist_ok=True)
selected=[];artifacts=[]
for fn in sorted(root.glob('*.zip')):
  b=fn.read_bytes();artifacts.append({'file':fn.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
  with zipfile.ZipFile(fn) as z:
    for f in z.infolist():
      if f.is_dir():continue
      p=PurePosixPath(f.filename)
      if p.is_absolute() or '..' in p.parts:raise ValueError('unsafe member')
      ext=p.suffix.lower()
      if ext in {'.log','.err','.out','.apk','.flat'} or p.name in {'debug-target'}:continue
      if ext not in {'.java','.c','.mjs','.html','.json','.txt','.xml'}:continue
      d=z.read(f)
      try:d.decode('utf-8')
      except UnicodeDecodeError:continue
      selected.append((fn.stem+'/'+f.filename,d))
with zipfile.ZipFile(ref) as z:
  for fn in ['REA_6_8_0_REFERENCE_MANIFEST.json','REA_6_8_0_PROTOCOL_AND_ERRORS.json','REA_6_8_0_GIT_VS_NPM_FILES.json']:
    selected.append(('reference/'+fn,z.read(fn)))
manifest={'schema':'rea-6.8.0.library-source-20261103','scope':'source code and reproducibility protocol only; binaries and logs excluded','original_source_archives':artifacts,'original_oracle_reference':{'archive':ref.name,'bytes':ref.stat().st_size,'sha256':hashlib.sha256(ref.read_bytes()).hexdigest()},'selected_count':len(selected),'items':[{'path':p,'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()} for p,d in selected],'strict_status':'source fixture recovery only; independent REA parity, error semantics, exact AST and tool execution not asserted'}
readme='''# REA 6.8.0: source-only cross-tool fixture recovery

This recovered set preserves the actual Java Ghidra script, C GDB target source, Node Chrome/CDP test, HTML/XML fixtures, reference protocol manifests and small tool/version/validation records from ChatGPT Library. It deliberately excludes APK binaries, compiled executable, logs, and the very large oracle JSON responses; original ZIP identities and hashes remain in SOURCE_MANIFEST.json.

To verify: sha256sum the tar.gz against Git sidecar, extract to a new empty directory, then check each path and SHA-256 against SOURCE_MANIFEST.json. Regenerating the full P0-P5 REA program behavior requires a compatible REA 6.8.0 runtime and external Ghidra/Chrome/GDB/Android tools, not bundled here. This is not a claim of passing parity or production eligibility.
'''
sel=selected+[('SOURCE_MANIFEST.json',(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()),('README_SOURCE_ONLY.md',readme.encode())]
iofile=io.BytesIO()
with gzip.GzipFile(fileobj=iofile,filename='',mode='wb',mtime=0,compresslevel=9) as gz:
 with tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as tar:
  for p,d in sorted(sel):
   m=tarfile.TarInfo(p);m.size=len(d);m.mtime=0;m.mode=0o644;m.uid=m.gid=0;m.uname=m.gname='';tar.addfile(m,io.BytesIO(d))
a=iofile.getvalue();manifest['bundle_bytes']=len(a);manifest['bundle_sha256']=hashlib.sha256(a).hexdigest()
base='rea-6-8-0-tool-fixtures-source-only-20261103.tar.gz'
(out/base).write_bytes(a);(out/(base+'.b64.txt')).write_text(base64.b64encode(a).decode()+'\n');(out/'rea-6-8-0-SOURCE_INDEX_20261103.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
for f in [out/base,out/(base+'.b64.txt'),out/'rea-6-8-0-SOURCE_INDEX_20261103.json']:
 d=f.read_bytes();print(f.name,len(d),hashlib.sha1(b'blob '+str(len(d)).encode()+b'\0'+d).hexdigest())
print('count',len(selected),'sha256',hashlib.sha256(a).hexdigest())
