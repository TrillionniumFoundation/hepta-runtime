#!/usr/bin/env python3
"""Full byte/AST/input-only admission before any stdio target application."""
from pathlib import Path
import argparse,ast,hashlib,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,source_evidence
from cases import validate,group,domain
def verify(source):
    source=Path(source);identity=source_evidence(source)
    for path in source.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
    target=(source/"target/binary_file.py").read_bytes();module=ast.parse(target)
    require(hashlib.sha256(target).hexdigest()=="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12",
        "unaltered original Python module")
    entry=module.body[-1]
    require(isinstance(entry,ast.If)and ast.dump(entry.test,include_attributes=False)==ast.dump(
        ast.parse("__name__ == '__main__'",mode="eval").body,include_attributes=False),"exact original terminal CLI entry")
    wrapper=(source/"scripts/fault_original.py").read_text()
    require('exec(compile(raw,str(target),"exec"),namespace)'in wrapper
        and 'entry=ast.Module(body=last.body,type_ignores=[])'in wrapper
        and 'return os.fstat(fd)'in wrapper,"unchanged helpers/CLI AST with real kernel fstat")
    b=source/"trusted-build"
    expected={"native/binary_read_body.hepta":"0ff27a8ba9a8a53ca7cd97054a8394c04023fd7cb84fe2406bf8d2b7e867f4ba",
        "asm/binary_read_body_callable.S":"07177c2a6861f88916bc47e89c462e28dd2dcc3a1ffaa101d1594be5b100274b",
        "asm/process_orphans.S":"f1d4e92b9d2ce68c68dcbc730950eaddaf3aa1093f143d34924c3eafc302e050",
        "native/path_error.hepta":"23a5e7ae451cda076a2caa910d10ac34ae0757922b55df538dab03746ed4ff9a",
        "asm/binary_read_stdio.S":"392e08f7077d7d5275b40c8c018920712dedc8f84c85a5386d0a5f250f3d0178"}
    for path,value in expected.items():require(pin(b/path)["sha256"]==value,"exact qualified production dependency")
    body=(b/"asm/binary_read_stdio.S").read_text()
    require(body.count("call hia_process_orphans_create")==1 and "mov rdx, [r15+112]"in body
        and "call binary_read_body_create"in body and "HBRLJR01"in body,"single pool and fixed lifecycle observer")
    result=validate()
    return dict(status="STDIO_READ67_SOURCE_AND_INPUT_ONLY_PASS",source=identity,domain=result,
        original_cli_ast_sha256=hashlib.sha256(ast.dump(ast.Module(body=entry.body,type_ignores=[]),include_attributes=False).encode()).hexdigest(),
        actual_application_calls=0,compiler_calls=0,all_source_literals_preserved=True)
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);a=p.parse_args()
    print(canonical(verify(a.source)).decode(),end="")
