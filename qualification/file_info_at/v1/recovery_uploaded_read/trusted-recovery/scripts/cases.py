"""Frozen inputs only for the exact original borrowed-parent info branch."""
import copy,os
def attribute(name,value=b""):return dict(name_hex=os.fsencode(name).hex(),value_hex=value.hex())
def regular(content=b"file info fixture bytes\n",mode=0o640,attrs=None,**kw):
    out=dict(kind="regular",mode=mode,content_hex=content.hex(),attributes=attrs or[]);out.update(kw);return out
def repeated(count,size):return [attribute("user.k%03d"%i,bytes([i%251])*size)for i in range(count)]
def cases():
    out=[]
    def add(group,name,spec=None,**kw):
        q=dict(id=len(out)+1,group=group,name=name,basename="data.bin",original_path="/configured/data.bin",
            file=regular()if spec is None else spec,filesystem="runner-temp",observer=True,actions=[],
            attempts=1,arm_fstat_error=False,control_fd0=None,fd_limit=False,close_parent_before=False,
            initial_quiet_seconds=.01,native_protocol_controls=False,expected_result=None)
        q.update(kw);out.append(q);return q
    def act(owner,op,n,effect,**kw):return dict(owner=owner,operation=op,occurrence=n,effect=effect,**kw)
    add("ordinary-a","empty",regular(b""))
    add("ordinary-a","ascii")
    add("ordinary-a","binary",regular(bytes(range(256))*17))
    add("ordinary-a","maximum-mode",regular(mode=0o7777))
    add("ordinary-a","hardlinks",regular(links=2))
    add("ordinary-a","quoted-unicode-name",basename='quote"\\\n-\u20ac-\U0001f600',original_path='/configured/quote"\\\n-\u20ac-\U0001f600')
    for size in(1048575,1048576,1048577):
        add("content-boundaries","hash-content-"+str(size),regular(bytes(i%251 for i in range(size))))
    add("content-boundaries","empty-original-echo",original_path="")
    add("content-boundaries","nonBMP-path-and-control",original_path="/configured/\U0010ffff/\x01/\x00/\"\\\n")
    add("ordinary-b","read-only",regular(mode=0o444))
    add("ordinary-b","user-binary-attributes",regular(attrs=[attribute("user.empty"),attribute("user.value",bytes(range(256))*4)]))
    add("ordinary-b","invalid-and-unicode-attribute-names",regular(attrs=[
        attribute(b"user.\xff",b"\0\xff"),attribute("user.\u20ac",b"euro"),attribute("user.\U0001f600",b"astral"),
        attribute(b'user.quote"slash\\line\n',b"controls")]))
    add("ordinary-b","ACL-summary",regular(attrs=[attribute("user.z",b"z")],acl="named-user"))
    add("ordinary-b","list-capacity-retry",regular(attrs=[attribute("user."+str(i)+"x"*245,b"x")for i in range(3)]))
    for size in(127,128,129):add("attribute-boundaries","value-"+str(size),regular(attrs=[attribute("user.value",bytes(i%251 for i in range(size)))]))
    add("attribute-boundaries","maximum-name",regular(attrs=[attribute("user."+"x"*250,b"v")]))
    add("refusals-a","missing",dict(kind="missing",mode=0o600,attributes=[]))
    add("refusals-a","directory",dict(kind="directory",mode=0o750,attributes=[]))
    add("refusals-a","fifo",dict(kind="fifo",mode=0o600,attributes=[]))
    add("refusals-a","symlink",dict(kind="symlink",mode=0o777,attributes=[]))
    add("refusals-a","unreadable",regular(mode=0))
    add("refusals-b","empty-name",basename="")
    add("refusals-b","embedded-NUL-name",basename="data\0.bin")
    add("refusals-b","too-long-name",basename="z"*256)
    add("refusals-b","closed-parent",close_parent_before=True)
    for effect,kw in(("append",dict(bytes_hex=b"append".hex())),("truncate",dict(size=1)),
        ("overwrite",dict(bytes_hex=b"FILE INFO fixture bytes\n".hex())),("chmod",dict(mode=0o600)),
        ("utime",dict(mtime_ns=123456789000000000)),("hardlink",{}),("unlink",{}),("replace",{})):
        add("hash-race-a"if len(out)<33 else"hash-race-b","hash-"+effect,
            actions=[act("read",6,3,effect,**kw)])
    add("reopen-race","parent-renamed-before-reopen",actions=[act("info",1,1,"rename-parent")])
    add("reopen-race","replace-before-reopen",actions=[act("info",1,1,"replace")])
    add("reopen-race","unlink-before-reopen",actions=[act("info",1,1,"unlink")])
    add("reopen-race","append-before-regular-stat",actions=[act("info",2,1,"append",bytes_hex=b"new".hex())])
    add("reopen-race","append-before-version-stat",actions=[act("info",2,2,"append",bytes_hex=b"new".hex())])
    add("reopen-race","replace-after-second-open",actions=[act("info",2,2,"replace")])
    add("metadata-gap","append-after-version-check",actions=[act("metadata",1,1,"append",bytes_hex=b"late".hex())])
    add("metadata-gap","chmod-after-version-check",actions=[act("metadata",1,1,"chmod",mode=0o600)])
    add("metadata-gap","xattr-after-version-check",actions=[act("metadata",1,1,"set-xattr",name_hex=b"user.new".hex(),value_hex=b"new".hex())])
    add("metadata-gap","replace-path-after-version-check",actions=[act("metadata",1,1,"replace")])
    add("metadata-gap","parent-renamed-during-metadata",actions=[act("metadata",1,1,"rename-parent")])
    add("metadata-race","append-between-metadata-stats",actions=[act("metadata",1,2,"append",bytes_hex=b"late".hex())])
    add("metadata-race","chmod-between-metadata-stats",actions=[act("metadata",1,2,"chmod",mode=0o600)])
    add("metadata-race","hardlink-between-metadata-stats",actions=[act("metadata",1,2,"hardlink")])
    add("metadata-race","remove-after-list",regular(attrs=[attribute("user.value",b"old")]),
        actions=[act("metadata",3,1,"remove-xattr",name_hex=b"user.value".hex())])
    add("metadata-race","replace-xattr-before-read",regular(attrs=[attribute("user.value",b"old")]),
        actions=[act("metadata",3,1,"set-xattr",name_hex=b"user.value".hex(),value_hex=b"new".hex())])
    add("large-a","maximum-xattr",regular(attrs=[attribute("user.value",bytes(i%251 for i in range(65536)))]),filesystem="existing-shm")
    add("large-a","attribute-count256",regular(attrs=repeated(256,0)),filesystem="existing-shm")
    add("large-a","attribute-count257",regular(attrs=repeated(257,0)),filesystem="existing-shm")
    add("large-b","value-budget4MiB",regular(attrs=repeated(64,65536)),filesystem="existing-shm")
    add("large-b","value-budget-over4MiB",regular(attrs=repeated(65,65536)),filesystem="existing-shm")
    add("descriptor","parent-is-FD0",control_fd0="parent")
    add("descriptor","owned-file-is-FD0",control_fd0="file")
    add("descriptor","single-free-FD",fd_limit=True)
    add("orphan-a","regular-fstat-real-kernel-EIO",arm_fstat_error=True)
    add("orphan-a","two-live-contexts-one-orphan-pool",arm_fstat_error=True,attempts=2)
    add("orphan-b","orphan-owned-FD0",arm_fstat_error=True,control_fd0="file")
    add("orphan-b","orphan-parent-FD0",arm_fstat_error=True,control_fd0="parent")
    add("orphan-b","orphan-single-free-FD",arm_fstat_error=True,fd_limit=True)
    observed=list(out)
    for index in(1,2,3,4,6,12,13,14,21,22,25,28):
        q=copy.deepcopy(observed[index-1]);q.update(id=len(out)+1,group="observer-off-a"if index<13 else"observer-off-b",
            name="off-"+q["name"],observer=False);out.append(q)
    for q in out:q["native_protocol_controls"]=q["id"]in(1,2)
    return out
def group(name):
    result=[q for q in cases()if q["group"]==name]
    if not result:raise ValueError("undeclared fixed info domain")
    return result
