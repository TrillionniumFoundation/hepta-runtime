# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Frozen input-only filesystem and ownership domain. No expected application outputs."""
from copy import deepcopy
from evidence_common import require
TOKEN="@FIXTURE@"
def file(path="parent/data.txt",data=b"first file\n",kind="regular",mode=0o600,links=1,target=None):
    return dict(path=path,kind=kind,content_hex=data.hex(),mode=mode,links=links,target=target)
def entry(path="parent/data.txt",root=""):
    return dict(root=TOKEN+("/"+root if root else ""),path=TOKEN+"/"+path)
def domain():
    rows=[]
    def add(group,name,files=None,request=None,**kw):
        q=dict(id=len(rows),group=group,name=name,files=[file()]if files is None else files,
            request=dict(files=[entry()])if request is None else request,observer=True,attempts=1,
            reuse_context=False,cleanup="explicit",control_fd0=False,fd_free=None,
            fault=None,actions=[],native_protocol_controls=False,filesystem="runner-temp")
        q.update(kw);rows.append(q)
    add("ordinary-a","ascii")
    add("ordinary-a","empty",files=[file(data=b"")])
    add("ordinary-a","unicode",files=[file(data="汉字 é e\u0301 🌍\n".encode())])
    add("ordinary-a","embedded-nul",files=[file(data=b"a\0b\n")])
    add("ordinary-b","utf8-bom",files=[file(data=b"\xef\xbb\xbftext\n")])
    add("ordinary-b","json-escaping",files=[file('parent/引号"\\\t.txt',b'"\t\n\\\x01\x1f')],
        request=dict(files=[entry('parent/引号"\\\t.txt')]))
    add("ordinary-b","two-files",files=[file(),file("parent/second.txt","second ❤\n".encode())],
        request=dict(files=[entry(),entry("parent/second.txt")]))
    add("ordinary-b","root-slash",request=dict(files=[dict(root="/",path=TOKEN+"/parent/data.txt")]))
    many=[file("parent/f%02d.txt"%i,("file %02d\n"%i).encode())for i in range(16)]
    add("sixteen","sixteen-files",files=many,request=dict(files=[entry(f["path"])for f in many]))
    add("ceilings-a","one-byte-empty",files=[file(data=b"")],request=dict(files=[entry()],max_file_bytes=1))
    add("ceilings-a","one-byte-full",files=[file(data=b"x")],request=dict(files=[entry()],max_file_bytes=1))
    add("ceilings-a","one-byte-over",files=[file(data=b"xx")],request=dict(files=[entry()],max_file_bytes=1))
    add("ceilings-a","default-file-ceiling",files=[file(data=b"x"*16384)])
    add("ceilings-b","maximum-file",files=[file(data=b"x"*65536)],
        request=dict(files=[entry()],max_file_bytes=65536,max_response_bytes=262144))
    add("ceilings-b","maximum-file-plus-one",files=[file(data=b"x"*65537)],
        request=dict(files=[entry()],max_file_bytes=65536,max_response_bytes=262144))
    add("ceilings-c","full-nested-response-budget",files=[file(data=b"\\"*400)],
        request=dict(files=[entry()],max_response_bytes=1024))
    add("ceilings-c","minimum-response-budget",request=dict(files=[entry()],max_response_bytes=1024))
    add("ceilings-c","unicode-byte-ceiling",files=[file(data="🌍".encode()*16384)],
        request=dict(files=[entry()],max_file_bytes=65536,max_response_bytes=262144))
    add("validate-a","empty-batch",request=dict(files=[]))
    add("validate-a","seventeen-files",request=dict(files=[entry("parent/f%02d"%i)for i in range(17)]))
    add("validate-a","zero-file-limit",request=dict(files=[entry()],max_file_bytes=0))
    add("validate-a","too-large-file-limit",request=dict(files=[entry()],max_file_bytes=65537))
    add("validate-b","negative-file-limit",request=dict(files=[entry()],max_file_bytes=-1))
    add("validate-b","small-response-limit",request=dict(files=[entry()],max_response_bytes=1023))
    add("validate-b","large-response-limit",request=dict(files=[entry()],max_response_bytes=262145))
    add("validate-b","duplicate-path-different-root",request=dict(files=[entry(),entry(root="parent")]))
    for name,path in (("traversal","parent/../data.txt"),("dot","parent/./data.txt"),
        ("empty-component","parent//data.txt"),("trailing-slash","parent/data.txt/")):
        add("validate-c",name,request=dict(files=[entry(path)]))
    add("validate-d","late-invalid-before-any-open",
        request=dict(files=[entry(),dict(root=TOKEN,path="relative")]))
    add("validate-d","nul-path",request=dict(files=[entry("parent/da\0ta")]))
    add("validate-d","relative-root",request=dict(files=[dict(root="relative",path=TOKEN+"/parent/data.txt")]))
    add("validate-d","path-over-byte-bound",request=dict(files=[entry("a"*4097)]))
    add("policy","outside-root",request=dict(files=[entry(root="other")]))
    add("policy","capability-root",request=dict(files=[entry("parent",root="parent")]))
    add("policy","runtime-sidecar",files=[file("parent/.hepta-owned")],request=dict(files=[entry("parent/.hepta-owned")]))
    add("policy","overlong-component",request=dict(files=[entry("parent/"+"x"*256)]))
    for kind in("missing","directory","fifo","symlink"):
        add("kinds-a",kind,files=[file(kind=kind,target="replacement.txt")])
    add("kinds-b","parent-symlink",files=[file(),file("alias",kind="symlink",target="parent")],
        request=dict(files=[entry("alias/data.txt")]))
    add("kinds-b","hardlink-two",files=[file(links=2)])
    add("kinds-b","mode-zero",files=[file(mode=0)])
    add("kinds-b","late-missing-file",request=dict(files=[entry(),entry("parent/missing.txt")]))
    for name,data in(("invalid-start",b"\xff"),("invalid-continuation",b"\xe1A"),
        ("truncated-sequence",b"ok\xf0\x9f"),("invalid-long-prefix",b"x"*4096+b"\x80")):
        add("utf8-files",name,files=[file(data=data)])
    def actor(effect,owner="body",op=2,occurrence=3,**extra):
        return dict(owner=owner,operation=op,occurrence=occurrence,attempt=1,
            effect=effect,path="parent/data.txt",**extra)
    for effect,extra in(("append",dict(bytes_hex=b"added".hex())),("truncate",dict(size=2)),
        ("overwrite",dict(bytes_hex=b"FIRST".hex())),("chmod",dict(mode=0o640)),
        ("utime",dict(mtime_ns=1234567890123456789)),("hardlink",{})):
        add("mutate-read-a"if effect in("append","truncate","overwrite")else"mutate-read-b",
            effect+"-before-after-stat",actions=[actor(effect,**extra)])
    for effect in("replace","unlink","rename-parent"):
        add("mutate-confirm",effect+"-before-confirm-walk",
            actions=[actor(effect,owner="parent1",op=1,occurrence=1)])
    add("mutate-confirm","hardlink-before-final-confirm-stat",actions=[actor("hardlink",occurrence=5)])
    add("late-mutation","replace-after-identity-check",
        actions=[actor("replace",op=3,occurrence=1)])
    add("late-mutation","independent-files-not-atomic",
        files=[file(),file("parent/second.txt",b"second file\n")],
        request=dict(files=[entry(),entry("parent/second.txt")]),
        actions=[dict(owner="parent0",operation=1,occurrence=2,attempt=1,effect="overwrite",
            path="parent/second.txt",bytes_hex=b"SECOND".hex())])
    for name,phase,role in(("source-first",23,0),("before-read",31,0),("after-read",41,0),
        ("confirm-first",23,1),("confirm-final",61,1)):
        add("fault-a"if role==0 else"fault-b",name+"-kernel-EIO",fault=dict(phase=phase,role=role))
    add("orphan-two","two-context-source-orphans",fault=dict(phase=23,role=0),attempts=2)
    add("orphan-two","same-context-confirm-orphans",fault=dict(phase=23,role=1),attempts=2,reuse_context=True)
    add("ownership-a","fd-zero-source",files=[file("parent/deep/data.txt")],
        request=dict(files=[entry("parent/deep/data.txt")]),control_fd0=True)
    add("ownership-a","two-context-pool",attempts=2)
    add("ownership-a","same-context-reuse",attempts=2,reuse_context=True)
    for free in(1,2,3):add("limits","only-"+str(free)+"-free-FDs",fd_free=free)
    add("eof","orphan-live-result-EOF",fault=dict(phase=23,role=0),cleanup="eof-borrow")
    add("eof","orphan-released-result-EOF",fault=dict(phase=23,role=1),cleanup="eof-idle")
    add("eof","normal-live-result-EOF",cleanup="eof-borrow")
    add("observer-off","off-ascii",observer=False)
    add("observer-off","off-utf8-error",files=[file(data=b"\xff")],observer=False)
    add("observer-off","off-two-context",observer=False,attempts=2)
    add("controls","native-private-controls",native_protocol_controls=True)
    add("shm","existing-shm-ordinary",filesystem="existing-shm")
    add("shm","existing-shm-replacement",filesystem="existing-shm",
        actions=[actor("replace",owner="parent1",op=1,occurrence=1)])
    require(len({r["name"]for r in rows})==len(rows),"unique fixed names")
    return rows
def group(name):
    values=[q for q in domain()if q["group"]==name];require(values,"unknown group")
    return values
def groups():return list(dict.fromkeys(q["group"]for q in domain()))
def actual_query(q,root):
    request=deepcopy(q["request"])
    for row in request["files"]:
        for k in("root","path"):row[k]=row[k].replace(TOKEN,str(root))
    return dict(request=request,observer=q["observer"],fault=q["fault"])
