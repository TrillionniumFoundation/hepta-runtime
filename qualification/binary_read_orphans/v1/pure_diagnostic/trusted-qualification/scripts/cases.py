"""Frozen inputs only for read67 regular-first-fstat process ownership."""
import copy
def regular(content=b"read orphan fixture bytes\n",mode=0o600,**kw):
    value=dict(kind="regular",mode=mode,content_hex=content.hex(),attributes=[]);value.update(kw);return value
def cases():
    out=[]
    def add(group,name,entry,mode,**kw):
        q=dict(id=len(out)+1,group=group,name=name,entry=entry,mode=mode,basename="data.bin",
            file=regular(),filesystem="runner-temp",observer=True,actions=[],attempts=1,reuse_context=False,
            arm=None,control_fd0=None,fd_limit=False,close_parent_before=False,cleanup="explicit",
            initial_quiet_seconds=.01,native_protocol_controls=False,offset=0,limit=0,
            expected_result=None)
        q.update(kw);out.append(q)
    entries=[("path","read"),("path","fingerprint"),("path","private"),("at","fingerprint"),("at","private")]
    for entry,mode in entries:add("ordinary",entry+"-"+mode,entry,mode,native_protocol_controls=entry=="at"and mode=="fingerprint")
    for arm in("first","second","last"):
        for entry,mode in entries:
            add(arm+"-path"if entry=="path"else arm+"-at",arm+"-"+entry+"-"+mode,entry,mode,arm=arm)
    for mode in("fingerprint","private"):
        add("descriptor","first-file-fd0-"+mode,"at",mode,arm="first",control_fd0="file")
        add("descriptor","first-parent-fd0-"+mode,"at",mode,arm="first",control_fd0="parent")
        add("descriptor","first-only-one-free-fd-"+mode,"at",mode,arm="first",fd_limit=True)
    for mode in("fingerprint","private"):
        add("sharing","two-contexts-"+mode,"at",mode,arm="first",attempts=2)
        add("sharing","two-generations-"+mode,"at",mode,arm="first",attempts=2,reuse_context=True)
    for mode in("fingerprint","private"):
        add("eof","EOF-with-result-"+mode,"at",mode,arm="first",cleanup="eof-borrow")
        add("eof","EOF-after-release-"+mode,"at",mode,arm="first",cleanup="eof-idle")
    for entry in("path","at"):
        add("refusals","nonregular-"+entry,entry,"fingerprint",file=dict(kind="directory",mode=0o700,attributes=[]))
        add("refusals","private-permissions-"+entry,entry,"private",file=regular(mode=0o640))
    add("unicode","first-unicode-at","at","fingerprint",arm="first",basename='quoted"\\\\\n-\u20ac-\U0001f600')
    add("unicode","first-unicode-path","path","read",arm="first",basename='quoted"\\\\\n-\u20ac-\U0001f600')
    for entry,mode in entries:add("observer-off",entry+"-"+mode,entry,mode,observer=False)
    return out
def group(name):
    result=[q for q in cases()if q["group"]==name]
    if not result:raise ValueError("unknown frozen input group")
    return result
def actual_query(q,root):
    out=copy.deepcopy(q)
    if q["entry"]=="at":request=dict(name=q["basename"])
    else:request=dict(root=str(root),path=str(root/"parent"/q["basename"]),op="private_read"if q["mode"]=="private"else q["mode"],
        offset=q["offset"],limit=q["limit"])
    out["request"]=request
    return out
