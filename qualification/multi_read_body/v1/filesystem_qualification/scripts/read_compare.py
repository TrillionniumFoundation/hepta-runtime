"""Compare original actual effects, object lifetimes, files and complete returned values."""
from pathlib import Path
import hashlib,json
from evidence_common import require,sha
from protocol import stat_decode,version
class Normalize:
    """Owned-object and timestamp-change relation comparison. Every raw field stays retained.
    Only the declared fixture actor mutates files. Replacement is precreated and old
    objects stay held through their last read; no freed numeric inode is reused."""
    def __init__(self,root):self.root=root;self.objects={};self.times={}
    def text(self,s):return s.replace(self.root,"$FIXTURE")if isinstance(s,str)else s
    def stat(self,value):
        identity=(value["st_dev"],value["st_ino"])
        if identity not in self.objects:self.objects[identity]=len(self.objects)
        obj=self.objects[identity]
        result={k:value[k]for k in("st_mode","st_uid","st_gid","st_nlink","st_size","st_rdev")}
        result["object"]=obj
        for field in("st_mtime_ns","st_ctime_ns"):
            table=self.times.setdefault((obj,field),{})
            if value[field]not in table:table[value[field]]=len(table)
            result[field+"_relation"]=table[value[field]]
        return result
    def apply(self,value):
        if isinstance(value,list):return[self.apply(v)for v in value]
        if not isinstance(value,dict):return self.text(value)
        if "st_dev"in value and"st_ino"in value:return self.stat(value)
        if value.get("exists")is False:
            return dict(exists=False,error={k:value["error"][k]for k in("type","errno")})
        if {"type","errno","message","exact_str","args_repr"}.issubset(value):
            return {k:self.apply(value[k])for k in("type","errno","filename","message","exact_str","args_repr")}
        return {k:self.apply(v)for k,v in value.items()}

class Projection:
    """Map actual opened descriptors by lifetime; never equate a reused FD number."""
    def __init__(self,case):
        self.case=case;self.norm=Normalize(case["fixture_root"]);self.live={};self.serial=0
    def snapshot(self,value):return self.norm.apply(value)
    def path(self,value):
        root=self.case["fixture_root"]
        return "$FIXTURE"+value[len(root):]if value==root or value.startswith(root+"/")else value
    def observed(self,value,path):
        if not value["ok"]:return dict(ok=False,type=value["error"]["type"],errno=value["error"]["errno"])
        st=value["stat"]
        # Exterior path components are independently observed and their complete
        # raw stat is retained. Their allocation/timestamps belong to the runner.
        if path==self.case["fixture_root"]or path.startswith(self.case["fixture_root"]+"/"):
            return dict(ok=True,stat=self.norm.stat(st))
        return dict(ok=True,mode=st["st_mode"],uid=st["st_uid"],gid=st["st_gid"])
    def effects(self,effects):
        out=[]
        for row in effects:
            owner,op,fd=row["owner"],row["operation"],row["fd"]
            if owner=="body"and op==4:continue # bookkeeping only; actual FD stays live
            is_dir=owner.startswith("parent");root_open=is_dir and op==1
            opening=(is_dir and op in(1,2))or(owner=="body"and op==1)
            closing=(is_dir and op==5)or(owner=="body"and op==3)
            canonical=dict(owner=owner,operation="root-open"if root_open else
                "directory-open"if is_dir and opening else"file-open"if opening else
                "close"if closing else"stat"if op==2 else"read")
            if root_open:
                require(fd==0 and row["name"]=="/","exact actual root open")
                parent=None;absolute="/"
            else:
                require(fd in self.live,"actual OS effect lacks live descriptor lifetime")
                parent=self.live[fd];canonical["fd"]=parent["token"];canonical["held_path"]=self.path(parent["path"])
                canonical["before"]=self.observed(row["hook"]["before"],parent["path"])
            actions=[]
            for action in row["hook"]["actions"]:
                actions.append(dict(input=action["input"],before=self.snapshot(action["before"]),after=self.snapshot(action["after"])))
            canonical["actions"]=actions
            if not root_open:canonical["after_actor"]=self.observed(row["hook"]["after"],parent["path"])
            if opening:
                if not root_open:
                    name=row["name"];require(type(name)is str and name not in("","/",".","..")and"/"not in name and"\0"not in name,
                        "actual openat component is singular")
                    absolute=parent["path"].rstrip("/")+"/"+name
                canonical.update(path=self.path(absolute),flags=720896 if is_dir else 657408)
                require(row["flags"]==canonical["flags"],"exact noncreating directory/file open flags")
            canonical["ok"]=row["ok"]
            if row["ok"]:
                if opening:
                    opened=row["value"];require(type(opened)is int and 0<=opened<=2147483647 and opened not in self.live,
                        "actual open returns a fresh descriptor lifetime")
                    token=self.serial;self.serial+=1;self.live[opened]=dict(token=token,path=absolute,owner=owner)
                    canonical["opened"]=token
                elif closing:
                    require(row["value"]in(None,0),"actual close return")
                    del self.live[fd]
                elif op==2:
                    canonical["stat"]=self.norm.stat(row["value"])
                else:
                    require(op==5 and owner=="body"and type(row["count"])is int,"declared real read")
                    raw=bytes.fromhex(row["value"]["bytes_hex"]);require(len(raw)<=row["count"],"actual read extent")
                    canonical.update(count=row["count"],data=raw.hex())
            else:
                canonical["errno"]=row["errno"]
                if closing:raise ValueError("This first profile does not inject close failures")
                if op==5 and owner=="body":canonical["count"]=row["count"]
            out.append(canonical)
        return out
    def fds(self,value,baseline):
        require(set(value)==set(baseline)|{str(fd)for fd in self.live},"real remaining descriptor extent")
        return [dict(token=entry["token"],path=self.path(entry["path"]),
            stat=self.norm.stat(value[str(fd)]["stat"]),target=self.norm.text(value[str(fd)]["target"]))
            for fd,entry in sorted(self.live.items(),key=lambda pair:pair[1]["token"])]

def original_effects(case,attempt):
    rows=[]
    for e in case["_original_events"]:
        if e["hook"]["attempt"]!=attempt:continue
        op=e["operation"];owner=e["owner"];args=e["args"]
        opening=(owner.startswith("parent")and op in(1,2))or(owner=="body"and op==1)
        row=dict(owner=owner,operation=op,fd=e["fd"],hook=e["hook"],ok=e["ok"],
            name=args["path"]if opening else"",flags=args["flags"]if opening else None,
            count=args.get("count"),value=e.get("value"),errno=None if e["ok"]else e["error"]["errno"])
        if opening:require(args["flags"]in(720896,657408)and not(args["flags"]&64),"noncreating original open")
        rows.append(row)
    return rows
def native_effects(case,attempt):
    rows=[]
    for e in case["_native_invocations"][attempt-1]["effects"]:
        owner,op=e["owner"],e["operation"];opening=(owner.startswith("parent")and op in(1,2))or(owner=="body"and op==1)
        ret=e["raw_result"];ok=ret>=0
        name="/"if owner.startswith("parent")and op==1 else e["name"][:-1].decode("utf-8")if opening else""
        if not ok:value=None
        elif opening:value=ret
        elif owner=="body"and op==2:value=stat_decode(e["data"])
        elif owner=="body"and op==5:value=dict(bytes_hex=e["data"].hex())
        else:value=0
        rows.append(dict(owner=owner,operation=op,fd=e["fd"],hook=e["hook"],ok=ok,
            name=name,flags=(720896 if owner.startswith("parent")else 657408)if opening else None,
            count=e["hook"]["a"]if owner=="body"and op==5 else None,value=value,errno=None if ok else-ret))
    return rows
def actual_files(case,attempt,effects):
    value=case["actual"]["chain"]["invocations"][attempt-1]["result"]
    if not value["ok"]:return []
    files=value["value"]["files"]
    body=[e for e in effects if e["owner"]=="body"and e["operation"]!=4]
    stats=[(i,e["value"])for i,e in enumerate(body)if e["operation"]==2 and e["ok"]]
    require(len(stats)==5*len(files),"all original regular/read/confirmation stat observations")
    rows=[]
    for i,file in enumerate(files):
        before_at,before=stats[5*i+1];after_at,after=stats[5*i+2]
        read=b"".join(bytes.fromhex(e["value"]["bytes_hex"])for e in body[before_at+1:after_at]
            if e["operation"]==5 and e["ok"])
        require(file["size"]==len(read) and file["sha256"]==sha(read)and file["text"].encode("utf-8")==read
            and file["version"]==version(before) and file["eof"]is True,"complete actual result tied to bytes and second stat")
        require(file["version"]==version(after)==version(stats[5*i+4][1])
            and before["st_nlink"]==after["st_nlink"]==stats[5*i+4][1]["st_nlink"]==1,"actual before/after/confirm identity")
        rows.append((file,before))
    return rows
def success_projection(case,attempt,effects,projection):
    result=case["actual"]["chain"]["invocations"][attempt-1]["result"];value=result["value"]
    raw=result["raw_json"];require(raw==json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")),"complete canonical actual JSON bytes")
    require(set(value)=={"files","atomic_snapshot","snapshot_scope","encoding","truncated"}
        and value["atomic_snapshot"]is False and value["snapshot_scope"]=="independent_file"
        and value["encoding"]=="utf-8"and value["truncated"]is False,"complete original multi-file result contract")
    if case["input"]["observer"]:files=actual_files(case,attempt,effects)
    else:
        files=[]
        for file in value["files"]:
            relative=Path(file["path"]).relative_to(Path(case["fixture_root"])).as_posix()
            entry=case["setup"]["entries"][relative];raw_data=bytes.fromhex(entry["content"]["hex"])
            require(file["version"]==version(entry["stat"])and file["size"]==len(raw_data)
                and file["sha256"]==sha(raw_data)and file["text"].encode()==raw_data,"observer-off actual result bound to immutable fixture")
            files.append((file,entry["stat"]))
    request=case["actual"]["chain"]["actual_query"]["request"]["files"]
    require(len(files)==len(request),"all requested complete files")
    rows=[]
    for (file,st),entry in zip(files,request):
        require(set(file)=={"path","size","version","sha256","text","eof"}and file["path"]==entry["path"]
            and file["eof"]is True,"exact complete file result and request path")
        rows.append(dict(path=projection.norm.text(file["path"]),size=file["size"],sha256=file["sha256"],
            text=file["text"],eof=True,version_object=projection.norm.stat(st)))
    return dict(value,files=rows)
def errors(original,native,a,b):
    left,right=original["error"],native["error"]
    require(left["type"]==right["type"]and left["errno"]==right["errno"]
        and a.norm.text(left["filename"])==b.norm.text(right["filename"]),"actual complete exception identity")
    require(a.norm.text(original["diagnostic"])==b.norm.text(native["_diagnostic"]),"actual complete original/native diagnostic bytes")
    if left["type"]=="UnicodeDecodeError":
        require(left["encoding"]=="utf-8"and left["start"]==right["start"]and left["end"]==right["end"]
            and len(bytes.fromhex(left["object_hex"]))==right["object_length"]
            and {"invalid start byte":1,"invalid continuation byte":2,"unexpected end of data":3}[left["reason"]]==right["reason_code"],
            "actual original strict UTF8 exception span/object/reason")
    else:require(a.norm.text(left["message"])==b.norm.text(right["message"]),"complete literal exception")
def compare(left,right):
    require(left["input"]==right["input"],"same complete frozen input")
    q=left["input"];a=Projection(left);b=Projection(right);ca=left["actual"]["chain"];cb=right["actual"]["chain"]
    require(a.snapshot(left["setup"])==b.snapshot(right["setup"]),"whole original/native setup")
    require(a.snapshot(ca["before"])==b.snapshot(cb["before"]),"whole pre-invocation filesystem")
    for attempt,(ra,rb)in enumerate(zip(ca["invocations"],cb["invocations"]),1):
        ea=original_effects(left,attempt)if q["observer"]else[]
        eb=native_effects(right,attempt)if q["observer"]else[]
        if q["observer"]:require(a.effects(ea)==b.effects(eb),"complete actual OS sequence, descriptor lifetimes and real mutations")
        va,vb=ra["result"],rb["result"];require(va["ok"]==vb["ok"],"actual success/error differs")
        if va["ok"]:
            require(success_projection(left,attempt,ea,a)==success_projection(right,attempt,eb,b),"complete actual returned multi-file value")
        else:errors(va,vb,a,b)
        if q["observer"]:
            require(a.fds(ra["fds_with_result"],ca["fds_before"])==b.fds(rb["fds_with_result"],cb["fds_before"]),
                "same actual surviving orphan objects")
            if "fds_after_release"in ra:
                require(a.fds(ra["fds_after_release"],ca["fds_before"])==b.fds(rb["fds_after_release"],cb["fds_before"]),
                    "release preserves actual original process-lifetime orphans")
    require(a.snapshot(ca["after"])==b.snapshot(cb["after"]),"whole post-call filesystem")
    require(a.snapshot(left["after_exit"])==b.snapshot(right["after_exit"]),"whole post-exit filesystem")
    return dict(input=q["id"],name=q["name"],attempts=q["attempts"],observer=q["observer"],
        actual_actors=len(q["actions"]),same_complete_files=True,same_result_and_diagnostic=True,
        same_real_os_and_orphan_lifetimes=q["observer"])
