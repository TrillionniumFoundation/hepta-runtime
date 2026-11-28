"""Frozen input-only configured-root domain; no original outputs are embedded."""
from pathlib import Path
import copy
import json
import struct
PACK=lambda *v:struct.pack("<"+"Q"*len(v),*v)
def host(*,target="private-target",mode="operator",read=("/data",),write=("/write",),allow_write=True,protected=()):
    return dict(ssh_target=target,remote_state_dir="/remote",execution_mode=mode,
        allow_write=allow_write,allowed_read_path_prefixes=list(read),
        allowed_write_path_prefixes=list(write),protected_path_prefixes=list(protected))
def query(name,host_name,path,write=False,mode="rpc"):
    return dict(name=name,host=host_name,path=path,write=write,mode=mode)
def groups():
    out=[]
    def add(name,hosts,rows):
        config=None if hosts is None else dict(state_dir="$STATE",controller_workspace_roots=[],hosts=hosts)
        out.append(dict(name=name,config=config,queries=rows))
    add("absent",None,[query("rpc","h","/data"),query("observe","h","/data",mode="observe"),
        query("bad-path","missing","relative"),query("write","h","/write",True),
        query("policy-absent","h","relative",True,"policy")])
    paths=["","relative","/~","/~/x","/data","/data/","/data/x","/data//x","/data/..",
        "/data/../x","/data/..hidden","/database","/data/nested","/data/nested/x",
        "//double","//double/x","/data/a/./b","/data/a/.../b","/data/\0name","/data/\u00e9/\u6587\u4ef6",
        "/","///","/write","/write/nest/x"]
    rows=[]
    for i,path in enumerate(paths):
        rows += [query("read-"+str(i),"h",path),query("observe-"+str(i),"h",path,mode="observe"),
                 query("write-"+str(i),"h",path,True)]
    rows += [query("policy-"+str(i),"h",path,False,"policy") for i,path in enumerate(paths[:6])]
    rows += [query("name-"+str(i),name,"/data") for i,name in enumerate(["private-target","missing","", "\u00e9", "h\0"])]
    add("operator",{"h":host(read=("/data","/data/nested","/data/nested/","//double"),
        write=("/write","/write/nest","/write/nest//"))},rows)
    add("isolated",{"h":host(mode="isolated",protected=("/data/secret",))},[
        query("operator-first","h","relative"),query("operator-observe","h","/data",mode="observe"),
        query("operator-write","h","/write",True),query("policy-read","h","/data",False,"policy"),
        query("policy-protected","h","/data/secret/x",False,"policy")])
    add("empty-roots",{"h":host(read=(),write=())},[
        query("no-read","h","/data"),query("no-write","h","/write",True),
        query("observe","h","/data",mode="observe")])
    add("disabled-write",{"h":host(allow_write=False)},[
        query("read","h","/data"),query("write","h","/write",True),
        query("write-path-first","h","relative",True),query("write-parent-first","h","/write/../x",True)])
    add("alias-collision",{
        "a":host(target="z",mode="isolated",read=("/alias","/named","/secret"),write=("/write",),
                 allow_write=False,protected=("/secret",)),
        "z":host(target="z-alias",read=("/named","/secret"),write=("/write",))},[
        query("named-root-missing","z","/alias/file"),query("named-root","z","/named/file"),
        query("protected-alias","z","/secret/file"),query("write-alias-denied","z","/write/file",True),
        query("isolated-named-first","a","relative"),query("unknown-before-path","missing","relative"),
        query("ssh-name-not-configured","z-alias","/named/file"),
        query("alias-policy","z-alias","/named/file",False,"policy"),
        query("observe-alias","z","/alias/file",mode="observe"),
        query("observe-named","z","/named/file",mode="observe")])
    add("alias-order",{
        "a":host(target="z",read=("/first",),write=("/write-first",)),
        "b":host(target="z",read=("/second",),write=("/write-second",)),
        "z":host(target="z-host",read=("/first","/second"),write=("/write-first","/write-second"))},[
        query("first","z","/first/x"),query("second-denied","z","/second/x"),
        query("first-write","z","/write-first/x",True),query("second-write","z","/write-second/x",True)])
    prefixes=["/","/a","/a/","/a//","/a///","//","//a","//a/","/\u00e9","/\u00e9/\u6587"]
    rows=[]
    for i,path in enumerate(["/","////","/a","/a/","/a/x","/ab","//a/x","///a/x","/\u00e9/\u6587/x"]):
        rows.extend([query("raw-read-"+str(i),"h",path),query("raw-write-"+str(i),"h",path,True)])
    add("raw-prefix-length",{"h":host(read=prefixes,write=tuple(reversed(prefixes)))},rows)
    add("large-name",{"h":host()},[query("unknown-name","n"*(8*1024*1024+257),"/data")])
    long_root="/"+("p"*(8*1024*1024+17))
    add("large-root",{"h":host(read=(long_root,))},[
        query("long-root","h",long_root+"/x"),query("long-root-exact","h",long_root,mode="observe")])
    names=[g["name"] for g in out]
    assert len(names)==len(set(names))==10
    for group in out:
        names=[q["name"] for q in group["queries"]]
        assert len(names)==len(set(names))
    return out
def materialized(folder):
    folder=Path(folder).absolute()
    result=groups()
    for group in result:
        if group["config"] is not None:
            group["config"]["state_dir"]=str(folder/group["name"]/"state")
    return result
def frame(query):
    host=query["host"].encode();path=query["path"].encode()
    return b"HRCFGQ01"+PACK(8 if query["mode"]=="policy" else 9,40+len(host)+len(path),0,0,
        int(query["write"]),len(host),len(path))+host+path
def controls():
    base=bytearray(frame(query("private","h","/data")))
    out=[]
    for name,at,value in [("user",24,1),("port",32,1),("write",40,2),
        ("name-overflow",48,(1<<64)-1),("path-overflow",56,(1<<64)-1),
        ("name-mismatch",48,0),("path-mismatch",56,0)]:
        raw=bytearray(base);struct.pack_into("<Q",raw,at,value);out.append((name,bytes(raw)))
    raw=bytearray(base);raw[64]=255;out.append(("host-utf8",bytes(raw)))
    raw=bytearray(base);raw[-1]=255;out.append(("path-utf8",bytes(raw)))
    out += [("short-owner",b"HRCFGQ01"+PACK(9,0)),("short-bridge",b"HRCFGQ01"),
            ("header-size",b"HRCFGQ01"+PACK(9,1))]
    return out
def encoded(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode()
