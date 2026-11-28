#!/usr/bin/env python3
"""Unedited original helpers and exact CLI AST; arm kernel EIO at first os.fstat."""
from pathlib import Path
import ast,os,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from real_fstat_fault import install
if len(sys.argv)!=2:raise SystemExit(111)
target=Path(sys.argv[1]).resolve(strict=True);raw=target.read_bytes();module=ast.parse(raw,filename=str(target))
last=module.body[-1]
if not isinstance(last,ast.If)or ast.dump(last.test,include_attributes=False)!=ast.dump(
    ast.parse("__name__ == '__main__'",mode="eval").body,include_attributes=False):raise ValueError("exact original CLI entry")
namespace=dict(__name__="frozen_original_helpers",__file__=str(target),__builtins__=__builtins__)
exec(compile(raw,str(target),"exec"),namespace)
class OriginalOS:
    armed=False
    def __getattr__(self,name):return getattr(os,name)
    def fstat(self,fd):
        if not self.armed:self.armed=True;install()
        return os.fstat(fd)
namespace["os"]=OriginalOS();namespace["__name__"]="__main__"
entry=ast.Module(body=last.body,type_ignores=[])
exec(compile(entry,str(target),"exec"),namespace)
