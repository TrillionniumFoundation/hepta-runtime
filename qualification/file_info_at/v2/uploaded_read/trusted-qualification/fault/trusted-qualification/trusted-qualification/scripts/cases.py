"""Frozen inputs only for the exact original borrowed-parent info branch."""
import copy,os
def attribute(name,value=b""):return dict(name_hex=os.fsencode(name).hex(),value_hex=value.hex())
def regular(content=b"file info fixture bytes\n",mode=0o640,attrs=None,**kw):
    out=dict(kind="regular",mode=mode,content_hex=content.hex(),attributes=attrs or[]);out.update(kw);return out
def repeated(count,size):return [attribute("user.k%03d"%i,bytes([i%251])*size)for i in range(count)]
def cases():
    out=[]
    def add(group,name,spec=None,**kw):
        q=dict(id=len(out)+1,group=group,name=name,basename="pool-v2.bin",original_path="/configured/rebind/pool-v2.bin",
            file=regular(b"new info shared-pool composition v2\n")if spec is None else spec,
            filesystem="runner-temp",observer=True,actions=[],attempts=1,arm_fstat_error=False,fault_owner=None,
            control_fd0=None,fd_limit=False,close_parent_before=False,initial_quiet_seconds=.01,
            native_protocol_controls=False,expected_result=None)
        q.update(kw);out.append(q);return q
    def act(owner,op,n,effect,**kw):return dict(owner=owner,operation=op,occurrence=n,effect=effect,**kw)
    add("ordinary","rebound-empty",regular(b""))
    add("ordinary","rebound-binary-xattrs",regular(bytes(range(255,-1,-1))*9,attrs=[
        attribute("user.rebind.empty"),attribute("user.rebind.bytes",bytes(range(64)))]))
    add("ordinary","rebound-quoted-unicode",regular(b"new Unicode metadata\n",links=2),
        basename='pool-v2-"\n-\u20ac-\U0001f642',original_path='/configured/rebind/\\\x01-\U0001f642')
    add("ordinary","rebound-large-hash",regular(bytes((i*17+3)%251 for i in range(65553))))
    add("errors","rebound-missing",dict(kind="missing",mode=0o600,attributes=[]))
    add("errors","rebound-fifo",dict(kind="fifo",mode=0o600,attributes=[]))
    add("errors","rebound-symlink",dict(kind="symlink",mode=0o777,attributes=[]))
    add("errors","rebound-unreadable",regular(b"new inaccessible input\n",mode=0))
    add("child-orphans","fingerprint-first-stat-EIO",arm_fstat_error=True,fault_owner="read")
    add("child-orphans","two-fingerprint-contexts-one-pool",arm_fstat_error=True,fault_owner="read",attempts=2)
    add("child-orphans","fingerprint-orphan-FD0",arm_fstat_error=True,fault_owner="read",control_fd0="file")
    add("child-orphans","fingerprint-borrowed-parent-FD0",arm_fstat_error=True,fault_owner="read",control_fd0="parent")
    add("child-orphans","fingerprint-single-free-FD",arm_fstat_error=True,fault_owner="read",fd_limit=True)
    add("child-orphans","fingerprint-parent-renamed-before-EIO",arm_fstat_error=True,fault_owner="read",
        actions=[act("read",6,1,"rename-parent")])
    add("outer-orphans","outer-first-stat-EIO",arm_fstat_error=True,fault_owner="info")
    add("outer-orphans","two-outer-contexts-one-pool",arm_fstat_error=True,fault_owner="info",attempts=2)
    add("outer-orphans","outer-orphan-FD0",arm_fstat_error=True,fault_owner="info",control_fd0="file")
    add("outer-orphans","outer-borrowed-parent-FD0",arm_fstat_error=True,fault_owner="info",control_fd0="parent")
    add("outer-orphans","outer-single-free-FD",arm_fstat_error=True,fault_owner="info",fd_limit=True)
    add("descriptor","rebound-parent-FD0",control_fd0="parent")
    add("descriptor","rebound-file-FD0",control_fd0="file")
    add("descriptor","rebound-single-free-FD",fd_limit=True)
    add("mutation","rebound-held-parent-rename",actions=[act("info",1,1,"rename-parent")])
    add("mutation","rebound-hash-mutation",actions=[act("read",6,3,"append",bytes_hex=b"new hash mutation\n".hex())])
    add("mutation","rebound-metadata-gap",actions=[act("metadata",1,1,"append",bytes_hex=b"new metadata gap\n".hex())])
    add("mutation","rebound-xattr-mutation",regular(b"new attributed input\n",attrs=[attribute("user.rebind.value",b"before")]),
        actions=[act("metadata",3,1,"set-xattr",name_hex=b"user.rebind.value".hex(),value_hex=b"after".hex())])
    add("shm","rebound-tmpfs-attributes",regular(b"tmpfs rebound bytes\n",attrs=[attribute("user.rebind.value",b"v"*1025)]),
        filesystem="existing-shm")
    add("shm","fingerprint-tmpfs-first-stat-EIO",arm_fstat_error=True,fault_owner="read",filesystem="existing-shm")
    for index in(1,2,5,7):
        q=copy.deepcopy(out[index-1]);q.update(id=len(out)+1,group="observer-off",
            name="off-"+q["name"],observer=False);out.append(q)
    for q in out:q["native_protocol_controls"]=q["id"]in(1,2)
    return out
def group(name):
    result=[q for q in cases()if q["group"]==name]
    if not result:raise ValueError("undeclared fixed info rebind domain")
    return result
