"""Complete owned filesystem accounting from source fixtures and actual effects."""
import copy,stat
from common import require,pin
from fixture import NAME,normalized
METADATA={"st_mode","st_uid","st_gid","st_nlink","st_size","st_dev","st_ino","st_atime_ns","st_mtime_ns","st_ctime_ns"}
KINDS={"file":stat.S_IFREG,"directory":stat.S_IFDIR,"symlink":stat.S_IFLNK,"fifo":stat.S_IFIFO}
def complete(rows,temporaries=()):
    require(type(rows) is list and rows and rows[0]["path_hex"]=="","complete rooted snapshot")
    paths=[]
    for row in rows:
        require(type(row) is dict and type(row["path_hex"]) is str,"snapshot row")
        path=bytes.fromhex(row["path_hex"]);paths.append(path)
        require(path==b"" or not path.startswith(b"/") and all(x not in (b"",b".",b"..") for x in path.split(b"/")),"owned relative path")
        st=row["stat"]
        require(set(st)==METADATA and all(type(x) is int for x in st.values()),"all exact metadata fields")
        require(st["st_dev"]>=0 and st["st_ino"]>0 and st["st_nlink"]>=1 and st["st_size"]>=0,"actual inode extent/identity")
        kind=row["kind"];require(kind in KINDS and stat.S_IFMT(st["st_mode"])==KINDS[kind],"matching actual type")
        keys={"path_hex","stat","kind"}
        if kind=="file":keys|={"data_hex","bytes","sha256"}
        if kind=="symlink":
            keys.add("target_hex");require(len(bytes.fromhex(row["target_hex"]))==st["st_size"],"complete symlink target")
        require(set(row)==keys,"all complete snapshot fields")
    require(len(set(paths))==len(paths),"unique complete paths")
    return normalized(rows,temporaries)
def emit(objects,names,root,uid,gid):
    result=[dict(path_hex="",kind=root["kind"],mode=root["mode"],uid=uid,gid=gid,
                 nlink=1 if root["kind"]=="file" else 2+sum(objects[k]["kind"]=="directory" for k in names.values()))]
    if root["kind"]=="file":
        result[0].update(data_hex=root["raw"].hex(),size=len(root["raw"]),hardlinks=[""])
    for name in sorted(names):
        key=names[name];obj=objects[key];kind=obj["kind"]
        row=dict(path_hex=name,kind=kind,mode=obj["mode"],uid=obj["uid"],gid=obj["gid"],
                 nlink=2 if kind=="directory" else sum(k==key for k in names.values()))
        if kind=="file":row.update(data_hex=obj["raw"].hex(),size=len(obj["raw"]),hardlinks=sorted(n for n,k in names.items() if k==key))
        if kind=="symlink":row["target_hex"]=obj["target"].hex()
        result.append(row)
    return sorted(result,key=lambda r:r["path_hex"])
def unpack(rows):
    rootrow=rows[0];require(rootrow["path_hex"]=="","root row")
    root=dict(kind=rootrow["kind"],mode=rootrow["mode"],raw=bytes.fromhex(rootrow.get("data_hex","")))
    objects={};names={}
    for row in rows[1:]:
        name=row["path_hex"];key=tuple(row["hardlinks"]) if row["kind"]=="file" else ("other",name)
        obj=dict(kind=row["kind"],mode=row["mode"],uid=row["uid"],gid=row["gid"],
                 raw=bytes.fromhex(row.get("data_hex","")),target=bytes.fromhex(row.get("target_hex","")))
        if key in objects:require(objects[key]==obj,"complete hardlinked inode contents")
        objects[key]=obj;names[name]=key
    return objects,names,root
def source_initial(case,uid,gid):
    objects={};names={};root=dict(kind=case["root_kind"],mode=KINDS[case["root_kind"]]|case["root_mode"],raw=b"borrowed-root-file")
    if case["root_kind"]=="file":
        root["mode"]=stat.S_IFREG|0o600
        return emit(objects,names,root,uid,gid)
    def add(name,kind,mode,raw=b"",target=b""):
        key=name.encode().hex();objects[key]=dict(kind=kind,mode=KINDS[kind]|mode,uid=uid,gid=gid,raw=raw,target=target);names[key]=key
    kind=case["kind"];raw=bytes.fromhex(case["data_hex"])
    if kind in ("file","hardlink"):add(NAME,"file",case["mode"],raw)
    if kind=="hardlink":names[b"second-link".hex()]=NAME.encode().hex()
    if kind=="directory":add(NAME,"directory",0o700)
    if kind=="fifo":add(NAME,"fifo",0o600)
    if kind=="symlink":add("target","file",0o600,raw);add(NAME,"symlink",0o777,target=b"target")
    require(kind in ("file","hardlink","directory","fifo","symlink","missing"),"source fixture")
    return emit(objects,names,root,uid,gid)
def before_step(case,step,before,previous,temporaries,uid,gid):
    actual=complete(before,temporaries)
    if previous is None:expected=source_initial(case,uid,gid)
    else:expected=complete(previous,temporaries)
    objects,names,root=unpack(expected)
    for action in step["actions"]:
        require(action=={"type":"unlink_anchor"} and NAME.encode().hex() in names,"fixed actual interturn removal")
        del names[NAME.encode().hex()]
    require(actual==emit(objects,names,root,uid,gid),"source fixture plus exact prior filesystem/interturn actions")
    return actual
def after_step(before,after,signature,temporaries,uid,gid):
    before_norm=complete(before,temporaries);objects,names,root=unpack(before_norm);positions={}
    def temporary(index):return ("@entropy-temporary-%04d"%index).encode().hex()
    for row in signature:
        op=row[0]
        if op=="open-temporary" and row[2]==0:
            name=temporary(row[1]);require(root["kind"]=="directory" and name not in names,"exclusive actual temporary creation")
            key=("new",row[1]);objects[key]=dict(kind="file",mode=stat.S_IFREG|0o600,uid=uid,gid=gid,raw=b"",target=b"")
            names[name]=key;positions["temporary-"+str(row[1])]=0
        elif op=="write":
            _,role,data,returned,err=row;raw=bytes.fromhex(data);index=int(role.split("-")[1]);name=temporary(index)
            require(name in names and role in positions,"write owns actual created temporary")
            if returned>=0:
                require(returned<=len(raw) and err==0,"actual complete/partial write")
                obj=objects[names[name]];at=positions[role]
                require(at==len(obj["raw"]),"sequential original write_all")
                obj["raw"]+=raw[:returned];positions[role]+=returned
        elif op=="link" and row[2]==0:
            name=temporary(row[1]);target=NAME.encode().hex()
            require(name in names and target not in names,"actual exclusive final hardlink")
            names[target]=names[name]
        elif op=="unlink" and row[2]==0:
            name=temporary(row[1]);require(name in names,"actual temporary unlink");del names[name]
    require(complete(after,temporaries)==emit(objects,names,root,uid,gid),"all actual effects account for every owned path, byte, permission and hardlink")
    old={r["path_hex"]:r for r in before};new={r["path_hex"]:r for r in after}
    # The operation never replaces an existing directory entry. Every surviving
    # old inode retains its identity/type/permission/owner and complete contents.
    for name,row in old.items():
        require(name in new,"publication does not remove a pre-existing entry")
        other=new[name]
        require(row["kind"]==other["kind"] and all(row["stat"][k]==other["stat"][k] for k in
                ("st_dev","st_ino","st_mode","st_uid","st_gid")),"every surviving pre-existing inode is unchanged")
        if row["kind"]=="file":
            require(row["data_hex"]==other["data_hex"] and all(row["stat"][k]==other["stat"][k] for k in
                    ("st_size","st_mtime_ns","st_ctime_ns")),"original existing file contents and mutation times unchanged")
        if row["kind"]=="symlink":require(row["target_hex"]==other["target_hex"],"existing symlink unchanged")
    return complete(after,temporaries)
def retired(folder,report,observations,by_case):
    from common import loads,read
    retirement=loads(read(folder/"RETIREMENT.json"));removed=loads(read(folder/"RETIRED.json"))
    require(set(retirement)=={"owned_root","device","inode","complete_final_observations","fixture_still_present"} and
            retirement["owned_root"]==report["root"] and retirement["fixture_still_present"] is True and
            type(retirement["device"]) is int and retirement["device"]>=0 and type(retirement["inode"]) is int and retirement["inode"]>0,
            "owned fixture identity before actual parent retirement")
    require(removed==dict(**retirement,removed_after_capture=True),"exact parent-owned post-exit retirement")
    last={r["case"]:r["after"] for r in observations};rows=retirement["complete_final_observations"]
    require(len(rows)==len(last) and [r["case"] for r in rows]==list(last),"all final owned case snapshots")
    for row in rows:
        require(set(row)=={"case","rows"} and complete(row["rows"],by_case[row["case"]])==complete(last[row["case"]],by_case[row["case"]]),
                "all final files captured before exact fixture removal")
    return pin(read(folder/"RETIRED.json"))
