#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Unedited target functions and an exact AST copy of the private-read branch."""
from pathlib import Path
import ast,copy,hashlib,json,os,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,sha
from filesystem import metadata,DIR
def send(value):
    raw=canonical(value);pending=memoryview(raw)
    while pending:
        count=os.write(1,pending);require(count>0,"reference response write");pending=pending[count:]
def take():
    raw=sys.stdin.buffer.readline()
    return None if not raw else decode(raw)
def hook(generation,call,operation,a=0,b=0,c=0):
    raw=b"HBRDHK01"+struct.pack("<7Q",generation,call,call,operation,a,b,c);pending=memoryview(raw)
    while pending:
        count=os.write(4,pending);require(count>0,"reference hook write");pending=pending[count:]
    ack=b""
    while len(ack)<8:
        part=os.read(5,8-len(ack));require(part,"reference hook EOF");ack+=part
    require(ack==bytes(8),"reference hook acknowledgement differs")
class Proxy:
    def __init__(self):self.generation=0;self.calls=0
    def __getattr__(self,name):return getattr(os,name)
    def notify(self,operation,a=0,b=0,c=0):
        self.calls+=1;hook(self.generation,self.calls,operation,a,b,c)
    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        operation=(1 if path=="/"else 2)if flags&os.O_DIRECTORY else 3
        self.notify(operation,dir_fd or 0)
        return os.open(path,flags,mode,dir_fd=dir_fd)
    def fstat(self,fd):self.notify(6,fd);return os.fstat(fd)
    def close(self,fd):self.notify(5,fd);return os.close(fd)
    def geteuid(self):self.notify(9);return os.geteuid()
def main():
    source=Path(sys.argv[1]);original=source/"trusted-build/target/binary_file.py";raw=original.read_bytes()
    ns=dict(__name__="qualified_binary_original",__file__=str(original))
    exec(compile(raw,str(original),"exec"),ns)
    module=ast.parse(raw);main_fn=next(n for n in module.body if isinstance(n,ast.FunctionDef)and n.name=="main")
    branches=[n for n in ast.walk(main_fn)if isinstance(n,ast.If)and isinstance(n.test,ast.Compare)
        and isinstance(n.test.left,ast.Name)and n.test.left.id=="op"
        and any(isinstance(v,ast.Constant)and v.value=="private_read"for v in n.test.comparators)]
    require(len(branches)==1,"private source branch differs");body=copy.deepcopy(branches[0].body)
    fn=ast.FunctionDef(name="private_at",args=ast.arguments(posonlyargs=[],args=[ast.arg(arg="fd"),ast.arg(arg="name")],
        vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]),body=body,decorator_list=[])
    wrapper=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
    require(ast.dump(ast.Module(body=body,type_ignores=[]),include_attributes=False)==
        ast.dump(ast.Module(body=branches[0].body,type_ignores=[]),include_attributes=False),"private branch AST changed")
    exec(compile(wrapper,str(original)+"#private_at","exec"),ns)
    binding=dict(original=pin(original),private_branch_ast_sha256=sha(ast.dump(ast.Module(body=body,type_ignores=[]),
        include_attributes=False).encode()),private_branch_exact=True,original_function_fingerprint_unchanged=True)
    hashlib.sha256(b"loaded").digest();proxy=Proxy();ns["os"]=proxy
    parent=None;query=None
    try:
        while message:=take():
            command=message["command"]
            if command=="hold":
                require(parent is None,"parent already held");query=message["query"]
                parent=os.open(query["parent"],DIR);proxy.generation=query["id"];proxy.calls=0
                send(dict(status="HELD",fd=parent,parent=metadata(os.fstat(parent)),binding=binding))
            elif command=="run":
                require(parent is not None and query is not None,"no held reference parent")
                try:
                    if query["entry"]=="at":
                        value=ns["fingerprint" if query["mode"]=="fingerprint"else"private_at"](parent,query["request"]["name"])
                    elif query["mode"]=="fingerprint":
                        fd,name=ns["parent"](query["request"]["root"],query["request"]["path"])
                        try:value=ns["fingerprint"](fd,name)
                        finally:proxy.close(fd)
                    else:value=ns["main"](query["request"])
                    result=dict(ok=True,value=value,canonical=canonical(value)[:-1].decode());diagnostic=None
                except Exception as error:
                    number=getattr(error,"errno",None)
                    result=dict(ok=False,error=dict(type=type(error).__name__,errno=number,
                        filename=getattr(error,"filename",None),message=str(error)if number is None else""))
                    diagnostic=type(error).__name__+": "+str(error)
                send(dict(status="RETURNED",result=result,diagnostic=diagnostic,parent=metadata(os.fstat(parent))))
            elif command=="release":
                require(parent is not None,"missing reference parent")
                value=metadata(os.fstat(parent));os.close(parent);parent=None;query=None
                send(dict(status="RELEASED",parent=value))
            else:raise ValueError("undeclared reference command")
        require(parent is None,"reference EOF with unreleased parent")
    finally:
        if parent is not None:os.close(parent)
if __name__=="__main__":main()
