# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Execute the exact target parent() body; observe held FDs outside that body."""
from pathlib import Path
import ast,os,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,sha
from filesystem import metadata
def write(fd,raw):
    pending=memoryview(raw)
    while pending:
        n=os.write(fd,pending);require(n>0,"reference write");pending=pending[n:]
def send(v):write(1,canonical(v))
def error(e):
    n=getattr(e,"errno",None)
    return dict(ok=False,error=dict(type=type(e).__name__,errno=n,filename=getattr(e,"filename",None),
        message=str(e)if n is None else""))
class Proxy:
    def __init__(self):self.generation=0;self.calls=0
    def __getattr__(self,n):return getattr(os,n)
    def notify(self,op,a=0):
        self.calls+=1;write(4,b"HPRDHK01"+struct.pack("<7Q",self.generation,self.calls,self.calls,op,a,0,0))
        ack=b""
        while len(ack)<8:
            part=os.read(5,8-len(ack));require(part,"reference ack EOF");ack+=part
        require(ack==bytes(8),"reference ack bytes")
    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        self.notify(1 if path=="/"and dir_fd is None else 2,0 if dir_fd is None else dir_fd)
        return os.open(path,flags,mode,dir_fd=dir_fd)
    def close(self,fd):self.notify(5,fd);return os.close(fd)
def main():
    source=Path(sys.argv[1]);original=source/"trusted-build/target/binary_file.py";raw=original.read_bytes()
    ns=dict(__name__="qualified_parent_original",__file__=str(original));exec(compile(raw,str(original),"exec"),ns)
    parent=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=="parent")
    binding=dict(original=pin(original),parent_ast_sha256=sha(ast.dump(parent,include_attributes=False).encode()),
        original_parent_unmodified=True)
    reserve=os.open("/dev/null",os.O_RDONLY|os.O_CLOEXEC);require(reserve==3,"fixed reference descriptor3")
    proxy=Proxy();ns["os"]=proxy;held=[None,None];last=[None,None];seq=[0,0];calls=[0,0]
    def close(s):
        require(held[s]is not None,"reference close without parent");fd=held[s];held[s]=None
        proxy.generation=seq[s];proxy.calls=calls[s]
        try:proxy.close(fd);value=dict(ok=True)
        except Exception as e:value=error(e)
        calls[s]=proxy.calls;return value
    try:
        while raw:=sys.stdin.buffer.readline():
            q=decode(raw);s=q["session"];require(s in(0,1),"session");cmd=q["command"]
            if cmd=="acquire":
                require(held[s]is None,"original still holds parent");seq[s]+=1
                proxy.generation=seq[s];proxy.calls=0
                try:
                    fd,name=ns["parent"](q["query"]["request"]["root"],q["query"]["request"]["path"])
                    held[s]=last[s]=fd;value=dict(ok=True,name=name,fd=fd)
                except Exception as e:value=error(e)
                calls[s]=proxy.calls;send(dict(result=value,binding=binding,generation=seq[s]))
            elif cmd=="stat":
                fd=last[s];require(fd is not None,"no last parent")
                try:value=dict(ok=True,metadata=metadata(os.fstat(fd)))
                except OSError as e:value=dict(ok=False,errno=e.errno)
                send(value)
            elif cmd=="close":send(close(s))
            else:raise ValueError("unknown reference command")
    finally:
        for s in(0,1):
            if held[s]is not None:
                require(close(s)==dict(ok=True),"original EOF close")
        os.close(reserve)
if __name__=="__main__":main()
