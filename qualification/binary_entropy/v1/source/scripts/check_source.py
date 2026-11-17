#!/usr/bin/env python3
"""Freeze all code, domain and exact actual CPython bytes before any application."""
from pathlib import Path
import argparse,ast,inspect,os,shutil,sys,uuid
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,pin,require,sha,source_evidence
PYTHON=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
def check(source,output):
    identity=source_evidence(source);count=0
    for path in source.rglob("*"):
        if path.is_file()and path.suffix in(".py",".pseudo"):
            ast.parse(path.read_bytes(),filename=str(path));count+=1
    domain=decode((source/"DOMAIN.json").read_bytes());cases=domain["cases"]
    require(domain["application_deadline_seconds"]==60 and domain["pure_deadline_seconds"]==180
        and domain["build_deadline_seconds"]==900 and len(cases)==42
        and len({q["name"]for q in cases})==42 and sum(len(q["modes"])for q in cases)==97,"complete fixed actual input domain")
    require(all(q["modes"]and all(m in(1,2)for m in q["modes"])and type(q["observer"])is bool for q in cases),
        "fixed raw16/UUID4 input modes")
    require(sys.version_info[:3]==(3,12,3)and sys.flags.isolated and sys.flags.no_site,"exact isolated CPython profile")
    python=Path(sys.executable).resolve(strict=True);uuid_path=Path(uuid.__file__).resolve(strict=True)
    require(pin(python)==PYTHON,"actual CPython interpreter differs from frozen image")
    actual=uuid_path.read_bytes();original=(source/"trusted-build/reference/cpython/Lib/uuid.py").read_bytes()
    require(actual in(original,original+b"\n",original[:-1]if original.endswith(b"\n")else original),
        "entire original UUID module differs beyond one terminal newline")
    require(inspect.isbuiltin(os.urandom)and os.urandom.__name__=="urandom"
        and os.urandom.__module__=="posix"and uuid.uuid4.__module__=="uuid","actual unchanged original entry bindings")
    require(not output.exists(),"fresh runtime custody");output.mkdir()
    shutil.copyfile(python,output/"python.bin");shutil.copyfile(uuid_path,output/"uuid.py")
    binding=dict(schema="hepta.runtime.binary-entropy.actual-cpython.v1",python=pin(python),uuid=pin(uuid_path),
        version=sys.version,python_path=str(python),uuid_path=str(uuid_path),urandom_builtin=True,
        uuid_module_whole_bytes_bound=True,source_sha256=sha(original),uuid4_source=inspect.getsource(uuid.uuid4))
    (output/"BINDING.json").write_bytes(encoded(binding))
    require(pin(output/"python.bin")==binding["python"]and pin(output/"uuid.py")==binding["uuid"],"whole retained runtime bytes")
    require(source_evidence(source)==identity,"source check changed frozen code")
    return dict(status="ENTROPY_SOURCE_DOMAIN_AND_ACTUAL_CPYTHON_PASS",source=identity,python_sources=count,
        cases=len(cases),applications_per_role=97,runtime=binding,application_calls=0)
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();print(encoded(check(a.source.resolve(strict=True),a.output.absolute())).decode(),end="")
