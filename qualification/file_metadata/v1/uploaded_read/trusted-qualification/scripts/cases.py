"""Frozen input-only descriptor metadata domains; no expected outcomes."""
import copy,json,os,struct
def attribute(name,value=b""):
    return dict(name_hex=os.fsencode(name).hex(),value_hex=value.hex())
def repeated(count,size):
    return [attribute("user.k%03d"%i,bytes([i%251])*size)for i in range(count)]
def unicode_attributes():
    return [attribute(b'user.quote"slash\\line\n',b"\0\xff"),attribute(b"user.\xff",b"bad"),
        attribute("user.\U0010ffff",b"max"),attribute("user.\u20ac",b"euro"),
        attribute("user.\U0001f600",b"astral"),attribute(b"user.empty"),attribute(b"user."+b"x"*250,b"long")]
def fixture(mode=0o640,attrs=None,**extra):
    out=dict(kind="regular",mode=mode,content_hex=b"metadata fixture bytes\n".hex(),attributes=attrs or []);out.update(extra);return out
def cases():
    out=[]
    def add(group,name,mode="capture-summary",source=None,target=None,**extra):
        row=dict(id=len(out)+1,group=group,name=name,mode=mode,
            source=fixture()if source is None else source,target=fixture(0o600)if target is None else target,
            filesystem="runner-temp",observer=True,actions=[]);row.update(extra);out.append(row)
    def action(operation,fd_role,occurrence,effect,**kw):
        return dict(operation=operation,fd_role=fd_role,occurrence=occurrence,effect=effect,**kw)
    add("capture-a","empty",source=fixture(content_hex=""))
    add("capture-a","regular-mode640")
    add("capture-a","unicode-and-invalid-byte-names",source=fixture(attrs=unicode_attributes()))
    for n in (127,128,129):add("capture-a","value-"+str(n),source=fixture(attrs=[attribute("user.value",bytes(i%251 for i in range(n)))]))
    add("capture-b","list-size-fallback",source=fixture(attrs=[attribute("user."+str(i)+"x"*245,b"x")for i in range(3)]))
    add("capture-b","ordinary-mode777",source=fixture(0o777))
    add("capture-b","capture-allows-hardlinks",source=fixture(links=2))
    add("capture-b","capture-held-unlinked-file",unlink_source_before=True)
    add("capture-b","source-fifo",mode="capture",source=dict(kind="fifo",mode=0o640,attributes=[]))
    add("capture-b","source-directory",mode="capture",source=dict(kind="directory",mode=0o750,attributes=[]))
    add("preserve-a","empty-to-empty","preserve")
    add("preserve-a","copy-and-remove-attributes","preserve",source=fixture(attrs=repeated(3,17)),
        target=fixture(0o777,attrs=[attribute("user.k001",b"old"),attribute("user.extra",b"remove")]))
    add("preserve-a","remove-all-extra-attributes","preserve",target=fixture(attrs=repeated(3,19)))
    add("preserve-a","binary-and-unicode-values","preserve",source=fixture(attrs=unicode_attributes()+[attribute("user.binary",bytes(range(256))*4)]))
    add("preserve-a","ACL-applied-last","preserve",source=fixture(attrs=[attribute("user.z",b"last-user"),attribute("user.a",b"first-user")],acl="named-user"),
        target=fixture(0o777,attrs=[attribute("user.extra",b"remove")],acl="named-group"))
    add("preserve-a","conditional-fchown-existing-group","preserve",source=fixture(gid=4))
    add("preserve-b","same-inode-separate-descriptors","preserve",target_is_source=True)
    add("preserve-b","source-hardlinks-refusal","preserve",source=fixture(links=2))
    add("preserve-b","source-unlinked-refusal","preserve",unlink_source_before=True)
    for bit,label in((0o4000,"setuid"),(0o2000,"setgid"),(0o1000,"sticky")):
        add("preserve-b","source-"+label+"-refusal","preserve",source=fixture(0o640|bit))
    add("preserve-c","existing-capability-refusal","preserve",source=dict(kind="preexisting",path="/usr/bin/ping",
        require_uid=0,require_nlink=1,require_capability_hex="0100000200200000000000000000000000000000"))
    add("preserve-c","existing-root-owner-fchown-refusal","preserve",source=dict(kind="preexisting",path="/etc/debian_version",
        require_uid=0,require_nlink=1,require_no_capability=True))
    add("preserve-c","target-directory-late-regular-check","preserve",target=dict(kind="directory",mode=0o777,attributes=[]))
    add("preserve-c","target-fifo-late-regular-check","preserve",target=dict(kind="fifo",mode=0o600,attributes=[]))
    add("preserve-c","target-hardlinks-retained","preserve",target=fixture(0o600,links=2))
    add("preserve-c","target-special-mode-cleared","preserve",target=fixture(0o7640))
    add("preserve-d","actual-closed-source","capture",close_source_before=True)
    add("preserve-d","actual-closed-target","preserve",close_target_before=True)
    add("preserve-d","target-existing-group-reset","preserve",target=fixture(gid=4))
    add("preserve-d","equal-attributes","preserve",source=fixture(attrs=repeated(4,9)),target=fixture(attrs=repeated(4,9)))
    add("preserve-d","remove-existing-ACL","preserve",target=fixture(0o777,acl="named-user"))
    add("preserve-d","source-shm-target-ext4","preserve",source=fixture(attrs=repeated(3,8),filesystem="existing-shm"))
    add("capture-race","append-between-capture-stats",actions=[action(2,"source",1,"append",role="source",bytes_hex=b"appended".hex())])
    add("capture-race","remove-attribute-after-list",source=fixture(attrs=[attribute("user.value",b"old")]),
        actions=[action(3,"source",1,"remove-xattr",role="source",name_hex=b"user.value".hex())])
    add("capture-race","chmod-between-capture-stats",actions=[action(1,"source",2,"chmod",role="source",mode=0o600)])
    add("capture-race","utime-between-capture-stats",actions=[action(1,"source",2,"utime",role="source",mtime_ns=123456789000000000)])
    add("capture-race","hardlink-between-capture-stats",actions=[action(1,"source",2,"hardlink",role="source")])
    add("capture-race","unlink-after-first-stat",actions=[action(2,"source",1,"unlink",role="source")])
    add("preserve-race-a","source-content-between-captures","preserve",
        actions=[action(5,"target",1,"append",role="source",bytes_hex=b"source-new-content".hex())])
    add("preserve-race-a","source-xattr-between-captures","preserve",source=fixture(attrs=[attribute("user.value",b"old")]),
        actions=[action(5,"target",1,"set-xattr",role="source",name_hex=b"user.value".hex(),value_hex=b"changed".hex())])
    add("preserve-race-a","source-link-count-between-captures","preserve",
        actions=[action(5,"target",1,"hardlink",role="source")])
    add("preserve-race-a","target-mode-before-verification","preserve",
        actions=[action(1,"target",2,"chmod",role="target",mode=0o600)])
    add("preserve-race-a","target-xattr-before-verification","preserve",source=fixture(attrs=[attribute("user.value",b"source")]),
        actions=[action(1,"target",2,"set-xattr",role="target",name_hex=b"user.value".hex(),value_hex=b"other".hex())])
    add("preserve-race-a","target-group-before-verification","preserve",
        actions=[action(1,"target",2,"chgrp",role="target",gid=4)])
    add("preserve-race-b","target-content-during-capture","preserve",
        actions=[action(1,"target",3,"append",role="target",bytes_hex=b"changed".hex())])
    add("preserve-race-b","source-mode-before-final-capture","preserve",
        actions=[action(1,"source",3,"chmod",role="source",mode=0o600)])
    add("preserve-race-b","same-size-source-content-before-final-capture","preserve",
        actions=[action(1,"source",3,"overwrite",role="source",bytes_hex=b"METADATA fixture bytes\n".hex())])
    add("preserve-race-b","target-chmod-after-verification","preserve",
        actions=[action(8,"target",1,"chmod",role="target",mode=0o600)])
    add("preserve-race-b","target-unlink-after-verification","preserve",
        actions=[action(8,"target",1,"unlink",role="target")])
    add("preserve-race-b","target-extra-removal-race","preserve",target=fixture(attrs=[attribute("user.extra",b"old")]),
        actions=[action(6,"target",1,"remove-xattr",role="target",name_hex=b"user.extra".hex())])
    add("large-a","maximum-value-fget-fallback",source=fixture(attrs=[attribute("user.value",bytes(i%251 for i in range(65536)))],filesystem="existing-shm"))
    add("large-a","attribute-count256",source=fixture(attrs=repeated(256,0),filesystem="existing-shm"))
    add("large-a","attribute-count257-budget",source=fixture(attrs=repeated(257,0),filesystem="existing-shm"))
    add("large-b","value-budget-exact4MiB",source=fixture(attrs=repeated(64,65536),filesystem="existing-shm"))
    add("large-b","value-budget-over4MiB",source=fixture(attrs=repeated(65,65536),filesystem="existing-shm"))
    add("large-c","preserve-maximum-value","preserve",source=fixture(attrs=[attribute("user.value",b"v"*65536)],filesystem="existing-shm"),
        target=fixture(filesystem="existing-shm"))
    add("large-c","maximum-name-list256",source=fixture(attrs=[attribute("user.%02x"%i+"x"*248)for i in range(256)],filesystem="existing-shm"))
    add("large-d","preserve-4MiB","preserve",source=fixture(attrs=repeated(64,65536),filesystem="existing-shm"),target=fixture(filesystem="existing-shm"))
    add("summary-a","owned-empty-summary","summary",snapshot=dict(uid=1001,gid=1001,mode=0o640,nlink="1",attributes=[]))
    add("summary-a","owned-unicode-summary","summary",snapshot=dict(uid=1001,gid=1001,mode=0o640,nlink="1",attributes=unicode_attributes()))
    add("summary-a","owned-u64-link-count","summary",snapshot=dict(uid=4294967295,gid=4294967295,mode=0o7777,nlink="18446744073709551615",attributes=[]))
    add("summary-a","owned-ACL-digest","summary",snapshot=dict(uid=0,gid=0,mode=0o600,nlink="0",attributes=[attribute("system.posix_acl_access",b"\0acl-bytes\xff")]))
    add("summary-b","owned-name-prefix-order","summary",snapshot=dict(uid=1001,gid=1001,mode=0o600,nlink="1",attributes=[attribute("user.abc",b"3"),attribute("user.a",b"1"),attribute("user.ab",b"2")]))
    add("summary-b","owned-256-invalid-byte-names","summary",snapshot=dict(uid=1001,gid=1001,mode=0o600,nlink="1",
        attributes=[attribute(("user.%02x"%i).encode()+b"\xff"*248,b"x")for i in range(256)]))
    add("summary-b","owned-control-and-nonBMP-names","summary",snapshot=dict(uid=1001,gid=1001,mode=0o600,nlink="1",
        attributes=[attribute("user.\0".replace("\0","\x01"),b"1"),attribute("user.\U00010000",b"2"),attribute("user.\uffff",b"3"),attribute(b"user.\x80",b"4")]))
    add("summary-b","owned-zero-length-values","summary",snapshot=dict(uid=1001,gid=1001,mode=0o600,nlink="1",attributes=repeated(12,0)))
    observed=list(out)
    for old in [observed[i-1] for i in (1,2,3,9,11,14,17,18,25,31,32,63)]:
        new=copy.deepcopy(old);new.update(id=len(out)+1,group="observer-off",name="off-"+old["name"],observer=False);out.append(new)
    for q in out:
        q["initial_quiet_seconds"]=0.01
        q["native_protocol_controls"]=q["id"] in(1,2)
        q["expected_result"]=None
    return out
def group(name):
    values=[x for x in cases()if x["group"]==name]
    if not values:raise ValueError("unknown fixed metadata domain")
    return values
def snapshot(spec):
    attributes=spec["attributes"];names=b"".join(bytes.fromhex(r["name_hex"])+b"\0"for r in attributes)
    values=b"".join(bytes.fromhex(r["value_hex"])for r in attributes);size=73856+len(values)
    raw=bytearray(size);raw[:8]=b"HMTSS001"
    struct.pack_into("<15Q",raw,8,1,spec["uid"],spec["gid"],spec["mode"],int(spec["nlink"]),0,
        len(attributes),len(names),len(values),size,0,128,8320,73856,0)
    at=8320;value=73856
    for i,r in enumerate(attributes):
        name=bytes.fromhex(r["name_hex"]);data=bytes.fromhex(r["value_hex"])
        struct.pack_into("<4Q",raw,128+i*32,at,len(name),value,len(data))
        raw[at:at+len(name)]=name;at+=len(name)+1;raw[value:value+len(data)]=data;value+=len(data)
    return bytes(raw)
def wire(mode,owned=b""):
    code={"capture":1,"capture-summary":1,"summary":2,"preserve":3}[mode]
    return b"HMDTQ001"+struct.pack("<11Q",1,0,code,0,0,len(owned),0,0,0,0,len(owned))+owned
def original_snapshot(spec):
    return dict(uid=spec["uid"],gid=spec["gid"],mode=spec["mode"],nlink=int(spec["nlink"]),flags=0,
        xattrs={os.fsdecode(bytes.fromhex(r["name_hex"])):bytes.fromhex(r["value_hex"])for r in spec["attributes"]},acl=None)
