#!/usr/bin/env python3
"""Small source and mechanical-read controls; no HIA or Rust execution."""
from __future__ import annotations
import argparse,ast,hashlib,importlib.util,io,json,os,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import read_only_guard as guard
import read_recovered as reader
import static_code_controls
import source_reconstruction_controls
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def main():
 p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 manifest=json.loads((HERE/"SOURCE_MANIFEST.json").read_bytes())
 expected=manifest["files"]
 actual={str(p.relative_to(HERE)) for p in HERE.rglob("*") if p.is_file()}
 reader.need(actual==set(expected)|{"SOURCE_MANIFEST.json"},"exact frozen recovery source set")
 for name,row in expected.items():
  path=HERE/name;data=path.read_bytes();info=path.lstat()
  reader.need(stat.S_ISREG(info.st_mode) and path.resolve()==path
   and len(data)==row["bytes"] and reader.sha(data)==row["sha256"]
   and hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()==row["git_blob"],
   "complete recovery source: "+name)
  if path.suffix==".py":ast.parse(data,filename=name)
 fixed=HERE/"reference/fixed_comparator.py"
 reader.source_function((reader.SOURCE/"scripts/compare_hia_runtime_rust.py").read_bytes(),fixed.read_bytes())
 tests=load("_original_prefix_regressions",HERE/"reference/test_public_control_checkpoint.py")
 tests.SOURCE=fixed
 stream=io.StringIO();outcome=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(tests))
 reader.need(outcome.wasSuccessful() and outcome.testsRun==8,"all eight existing prefix controls")
 negative=[]
 with tempfile.TemporaryDirectory(prefix="hia-history-read-controls-") as tmp:
  home=Path(tmp);source=home/"source";compiler=home/"compiler";owned=home/"owned"
  source.mkdir();(compiler/"docs").mkdir(parents=True);owned.mkdir()
  (compiler/"docs/HIA_SELFHOST_CORE_SUPPORT.json").write_text('{"source_identity":{"files":{}}}\n')
  (owned/"nested").mkdir();(owned/"nested/payload").write_bytes(b"complete nested payload")
  (owned/"CAPTURE.json").write_bytes(b'{"retained":true}\n');foreign=home/"foreign";foreign.write_bytes(b"outside")
  adapter=reader.MechanicalReads(source,compiler)
  command=["git","-C",str(source),"rev-parse","--show-toplevel"]
  kwargs={"capture_output":True,"text":True,"timeout":15}
  key=adapter.key((command,),kwargs)
  adapter.cache[key]=subprocess.CompletedProcess(command,128,"","not a repository\n")
  adapter.phase="replay"
  result=adapter.run(command,**kwargs)
  reader.need((result.returncode,result.stdout,result.stderr)==(128,"","not a repository\n"),"complete recorded metadata replay")
  original_capture=reader.CAPTURE;reader.CAPTURE=owned
  def refuses(label,fn):
   try:fn()
   except (ValueError,OSError,PermissionError):negative.append(label)
   else:raise ValueError("mechanical reader admitted "+label)
  try:
   before=guard.snapshot([owned]);adapter.mkdir(owned,mode=0o700,parents=True,exist_ok=True)
   reader.need(guard.snapshot([owned])==before,"existing directory no-op changed metadata")
   refuses("new-directory",lambda:adapter.mkdir(owned/"absent",exist_ok=True))
   refuses("existing-foreign-directory",lambda:adapter.mkdir(source,exist_ok=True))
   refuses("create-only-existing-directory",lambda:adapter.mkdir(owned,exist_ok=False))
   refuses("undeclared-process",lambda:adapter.run(["/bin/true"]))
   refuses("modified-metadata-deadline",lambda:adapter.run(command,capture_output=True,text=True,timeout=16))
   refuses("uncaptured-declared-metadata",lambda:adapter.run(["git","-C",str(source),"rev-parse","HEAD"],**kwargs))
  finally:reader.CAPTURE=original_capture
  proof=guard.guarded(lambda:{"bytes":(owned/"CAPTURE.json").read_bytes().hex()},roots=[owned],foreign_path=foreign)
  reader.need(len(proof["probes"])==12 and proof["before"]==proof["after"],"all original read-only guards")
  flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
  def descriptor_read():
   rootfd=os.open(owned,flags)
   try:
    nested=os.open(b"nested",flags,dir_fd=rootfd)
    try:
     child=os.open(b"payload",os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=nested)
     with os.fdopen(child,"rb") as stream:first=stream.read()
    finally:os.close(nested)
    child=os.open("CAPTURE.json",os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rootfd)
    with os.fdopen(child,"rb") as stream:second=stream.read()
    return [first.hex(),second.hex()]
   finally:os.close(rootfd)
  descriptor_proof=guard.guarded(descriptor_read,roots=[owned],foreign_path=foreign)
  reader.need(descriptor_proof["evidence"]==[b"complete nested payload".hex(),b'{"retained":true}\n'.hex()]
   and descriptor_proof["before"]==descriptor_proof["after"],"descriptor-relative complete reads")
  descriptor_refusals=[]
  initial_fd=os.open(owned,flags);foreign_fd=os.open(source,flags)
  def relative_attempt(name,open_flags):
   base=os.open(owned,flags)
   try:
    fd=os.open(name,open_flags,dir_fd=base)
    os.close(fd)
   finally:os.close(base)
  def replaced_attempt():
   base=os.open(owned,flags)
   try:
    os.dup2(foreign_fd,base)
    fd=os.open("CAPTURE.json",os.O_RDONLY|os.O_NOFOLLOW,dir_fd=base)
    os.close(fd)
   finally:os.close(base)
  def absolute_attempt(path,open_flags):
   fd=os.open(path,open_flags)
   os.close(fd)
  def unadmitted_attempt():
   fd=os.open("CAPTURE.json",os.O_RDONLY,dir_fd=initial_fd)
   os.close(fd)
  descriptor_cases=[
   ("directory-no-follow-required",lambda:absolute_attempt(owned,os.O_RDONLY|os.O_DIRECTORY)),
   ("foreign-directory",lambda:absolute_attempt(source,flags)),
   ("preexisting-directory-descriptor",unadmitted_attempt),
   ("relative-parent-escape",lambda:relative_attempt("../foreign",os.O_RDONLY|os.O_NOFOLLOW)),
   ("replaced-directory-descriptor",replaced_attempt),
   ("relative-descriptor-write",lambda:relative_attempt("CAPTURE.json",os.O_WRONLY)),
  ]
  try:
   for label,operation in descriptor_cases:
    before=guard.snapshot([owned])
    try:guard.guarded(operation,roots=[owned],foreign_path=foreign)
    except PermissionError as exc:
     descriptor_refusals.append({"name":label,"refusal":str(exc)})
    else:raise ValueError("descriptor guard admitted "+label)
    reader.need(guard.snapshot([owned])==before,"descriptor refusal changed full owned tree")
  finally:
   os.close(initial_fd);os.close(foreign_fd)

 static_controls=static_code_controls.run(reader.SOURCE/"scripts/hia_native_loader.py")
 reconstruction_controls=source_reconstruction_controls.run(reader.SOURCE)
 result={"schema":"hepta.history.recovery-source-controls.v1","status":"PASS",
  "source_files":len(expected),"source_manifest_sha256":reader.sha((HERE/"SOURCE_MANIFEST.json").read_bytes()),
  "prefix_regressions":8,"prefix_stdout":stream.getvalue(),"mechanical_refusals":negative,
  "guard_refusals":proof["probes"],"descriptor_complete_reads":2,
  "descriptor_refusals":descriptor_refusals,"static_code_controls":static_controls,
  "source_reconstruction_controls":reconstruction_controls,"native_or_rust_executions":0}
 reader.put(a.output,result)
 print(json.dumps({"status":"PASS","prefix_regressions":8,"mechanical_refusals":len(negative),"guard_refusals":12,"descriptor_complete_reads":2,"descriptor_refusals":len(descriptor_refusals),"static_code_refusals":len(static_controls["refusals"]),"source_generator_admissions":2,"source_reconstruction_refusals":len(reconstruction_controls["refusals"])},sort_keys=True))
if __name__=="__main__":main()
