#!/usr/bin/env python3
"""Freeze the actual interpreter/module bytes and compile source ASTs without target applications."""
from pathlib import Path
import ast,base64,binascii,fcntl,hashlib,json,os,platform,signal,stat,sys,uuid
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,pin,require,source_evidence
def capture(source,output):
    require(not output.exists(),"fresh runtime preflight");output.mkdir(parents=True)
    require(platform.machine()=="x86_64"and sys.platform=="linux"and sys.version_info[:3]==(3,12,3)
        and sys.getfilesystemencoding()=="utf-8"and sys.getfilesystemencodeerrors()=="surrogateescape",
        "fixed actual original platform")
    python=Path(sys.executable).resolve(strict=True)
    expected=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
    require(pin(python)==expected and signal.getsignal(13)==signal.getsignal(25)==signal.SIG_IGN,"actual original interpreter/signal profile")
    modules={}
    for name,module in(("base64",base64),("binascii",binascii),("fcntl",fcntl),("hashlib",hashlib),("json",json),("os",os),("uuid",uuid)):
        origin=module.__spec__.origin
        if not hasattr(module,"__file__"):
            require(name in sys.builtin_module_names and origin=="built-in","actual built-in module provenance")
            path=python;out=output/"python.elf";kind="built-in-elf"
        else:
            path=Path(module.__file__).resolve(strict=True);out=output/(name+path.suffix);kind="module-file"
        raw=path.read_bytes()
        if out.exists():require(out.read_bytes()==raw,"one shared actual builtin ELF")
        else:out.write_bytes(raw)
        require(pin(out)==pin(path),"complete actual standard-library input")
        modules[name]=dict(path=str(path),copy=out.name,kind=kind,origin=origin,interpreter=expected,**pin(out))
    syntax=[]
    for path in sorted(source.rglob("*.py")):
        compile(path.read_bytes(),str(path),"exec",flags=ast.PyCF_ONLY_AST);syntax.append(path.relative_to(source).as_posix())
    import read_capture,read_write_journal,read_publish_journal,read_metadata_journal,read_read_journal,physical_controls
    result=dict(status="SOURCE_AND_RUNTIME_ONLY_PASS",source=source_evidence(source),python=expected,
        python_version=list(sys.version_info[:3]),modules=modules,syntax=syntax,
        platform=dict(machine=platform.machine(),kernel=platform.release(),uid=os.geteuid(),gid=os.getegid()),
        signal_profile={"13":1,"25":1},original_write_application_calls=0,native_write_application_calls=0)
    (output/"RUNTIME.json").write_bytes(encoded(result));return result
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();print(encoded(capture(a.source.resolve(strict=True),a.output.absolute())).decode(),end="")
