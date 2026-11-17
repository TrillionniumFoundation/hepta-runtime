"""Entire fixed source corpus, actual original streams, and complete owned trees."""
from pathlib import Path
import copy,stat,struct
from common import ROOT,loads,pin,read,require,source,files
from protocol import cases,initial,word,validate_semantic
from fixture import NAME,normalized

METADATA={"st_mode","st_uid","st_gid","st_nlink","st_size","st_dev","st_ino","st_atime_ns","st_mtime_ns","st_ctime_ns"}
def complete(rows):
    require(type(rows) is list and rows and rows[0]["path_hex"]=="","complete rooted snapshot")
    paths=[]
    for row in rows:
        path=bytes.fromhex(row["path_hex"]);paths.append(path)
        require(path==b"" or not path.startswith(b"/") and all(x not in (b"",b".",b"..") for x in path.split(b"/")),"owned relative path")
        require(set(row["stat"])==METADATA and all(type(x) is int for x in row["stat"].values()),"every exact metadata field")
        require(row["stat"]["st_dev"]>=0 and row["stat"]["st_ino"]>0 and row["stat"]["st_nlink"]>=1,"actual inode identity")
        keys={"path_hex","stat","kind"}
        if row["kind"]=="file":keys|={"data_hex","bytes","sha256"}
        elif row["kind"]=="symlink":keys.add("target_hex")
        else:require(row["kind"] in ("directory","fifo"),"owned file type")
        require(set(row)==keys,"all snapshot fields")
    require(len(set(paths))==len(paths),"unique complete paths")
    return normalized(rows)

def model(case,steps,uid,gid):
    objects={};names={}
    def add(name,kind,mode,raw=b"",target=None,identity=None):
        key=identity or name;objects[key]=dict(kind=kind,mode=mode,raw=raw,target=target);names[name]=key
    kind=case["kind"];raw=bytes.fromhex(case["data_hex"])
    if kind in ("file","hardlink"):
        add(NAME,"file",case["mode"],raw)
        if kind=="hardlink":names["second-link"]=NAME
    elif kind=="directory":add(NAME,"directory",0o700)
    elif kind=="fifo":add(NAME,"fifo",0o600)
    elif kind=="symlink":
        add("target","file",0o600,raw);add(NAME,"symlink",0o777,target="target")
    else:require(kind=="missing","source fixture kind")
    for si,step in enumerate(steps):
        for ai,action in enumerate(step["actions"]):
            typ=action["type"]
            if typ=="chmod":objects[names[NAME]]["mode"]=action["mode"]
            elif typ=="write":objects[names[NAME]]["raw"]=bytes.fromhex(action["data_hex"])
            elif typ in ("read","mtime"):require(NAME in names,"existing source action target")
            elif typ=="unlink":del names[NAME]
            elif typ=="replace":add(NAME,"file",action["mode"],bytes.fromhex(action["data_hex"]),identity=("replacement",si,ai))
            elif typ=="link":names["additional-link"]=names[NAME]
            elif typ=="rename":names["renamed-anchor"]=names.pop(NAME)
            elif typ=="unrelated":add("unrelated","file",0o600,bytes.fromhex(action["data_hex"]))
            else:raise ValueError("source-owned action")
    rows=[dict(path_hex="",kind="directory",mode=stat.S_IFDIR|0o700,uid=uid,gid=gid,
               nlink=2+sum(objects[k]["kind"]=="directory" for k in names.values()))]
    for name in sorted(names):
        key=names[name];obj=objects[key];typ=obj["kind"]
        v=dict(path_hex=name.encode().hex(),kind=typ,mode=dict(file=stat.S_IFREG,directory=stat.S_IFDIR,fifo=stat.S_IFIFO,symlink=stat.S_IFLNK)[typ]|obj["mode"],
               uid=uid,gid=gid,nlink=2 if typ=="directory" else sum(x==key for x in names.values()))
        if typ=="file":v.update(data_hex=obj["raw"].hex(),size=len(obj["raw"]),hardlinks=sorted(n.encode().hex() for n,k in names.items() if k==key))
        if typ=="symlink":v["target_hex"]=obj["target"].encode().hex()
        rows.append(v)
    return rows

def owned_step(case,steps,before,after,uid,gid):
    expected=model(case,steps,uid,gid)
    require(complete(before)==complete(after)==expected,"complete source-owned fixture and read-only operation")
    for a,b in zip(before,after):
        require(a["path_hex"]==b["path_hex"] and all(a["stat"][k]==b["stat"][k] for k in METADATA-{"st_atime_ns"}),
                "every non-access-time inode field unchanged by actual anchor operation")

def initial_files(case,rows,uid,gid):
    require(complete(rows)==model(case,[],uid,gid),"complete initial source-owned fixture")

def verify(root,metadata,native):
    domain=cases(ROOT);folder=root/"original"
    require(set(files(folder))=={"ORIGINAL.json","OBSERVATIONS.json","RETIREMENT.json","process.json","original.stdin","original.stdout","original.stderr"},"complete original file set")
    report=loads(read(folder/"ORIGINAL.json"));process=loads(read(folder/"process.json"));observations=loads(read(folder/"OBSERVATIONS.json"))
    require(report["schema"]=="hepta.audit-pinned-anchor.original.v1" and report["status"]=="PASS" and report["source_manifest_sha256"]==source() and
            report["cases"]==len(domain) and report["operations"]==len(observations)==sum(len(c["steps"]) for c in domain),"all actual original cases")
    require(process["success"] is True and type(process["exit_code"]) is int and process["exit_code"]==0 and
            all(type(process[k]) is int and process[k]>1 for k in ("pid","parent_pid","pgid")) and process["pid"]!=process["parent_pid"] and process["pgid"]!=process["pid"] and
            process["timeout_seconds"]==60 and type(process["elapsed_seconds"]) in (int,float) and 0<=process["elapsed_seconds"]<=60 and
            process["owned_root"]==metadata["owned_fixture"] and process["source_root"]==metadata["source_root"] and
            process["argv"]==[str(Path(metadata["producer_root"])/"original.elf"),metadata["owned_fixture"]] and
            process["trace_environment_absent"] is True and process["binary"]==metadata["original_binary"],"actual original process/deadline/identity")
    for kind in ("stdin","stdout","stderr"):require(pin(read(folder/("original."+kind)))==process[kind],"complete original stream")
    stdin=b"".join(struct.pack("<2Q",ci,len(w))+w for ci,c in enumerate(domain) for si,s in enumerate(c["steps"]) for w in [initial(ci,si,s)])
    require(read(folder/"original.stdin")==stdin,"all exact original framed requests")
    stdout=bytearray();index=0;error_generations=set()
    for ci,case in enumerate(domain):
        for si,step in enumerate(case["steps"]):
            row=observations[index];other=native["observations"][index];index+=1;wire=initial(ci,si,step)
            require(set(row)=={"case","step","initial_hex","semantic_hex","before","after"} and
                    row["case"]==ci and row["step"]==si and row["initial_hex"]==wire.hex() and
                    row["semantic_hex"]==other["semantic_hex"],"all source/original/native semantic bytes")
            raw=validate_semantic(bytes.fromhex(row["semantic_hex"]));stdout+=struct.pack("<Q",len(raw))+raw
            if word(raw,8):error_generations.add(word(wire,16))
            owned_step(case,case["steps"][:si+1],row["before"],row["after"],metadata["uid"],metadata["gid"])
            require(all(complete(row[k])==complete(other[k]) for k in ("before","after")),"every original/native filesystem byte and policy field")
    require(read(folder/"original.stdout")==bytes(stdout),"complete actual original stdout")
    lines=read(folder/"original.stderr").splitlines();cursor=0;errors=[]
    for ci,case in enumerate(domain):
        for si,step in enumerate(case["steps"]):
            gen=1+ci*100+si
            require(cursor<len(lines) and lines[cursor]==("ANCHOR_ORIGINAL_BEGIN %d %d"%(ci,gen)).encode(),"exact original begin");cursor+=1
            if gen in error_generations:
                prefix=b"OBSERVED_ORIGINAL_ERROR "
                require(cursor<len(lines) and lines[cursor].startswith(prefix),"complete actual original error");error=loads(lines[cursor][len(prefix):]);cursor+=1
                require(set(error)=={"generation","display","debug","chain"} and error["generation"]==gen and
                        all(type(error[k]) is str for k in ("display","debug")) and type(error["chain"]) is list and error["chain"] and
                        all(type(x) is str for x in error["chain"]) and error["chain"][0]==error["display"],"all original error display/debug/chain")
                errors.append(error)
            require(cursor<len(lines) and lines[cursor]==("ANCHOR_ORIGINAL_END %d %d"%(ci,gen)).encode(),"exact original end");cursor+=1
    require(cursor==len(lines),"no unbound original stderr")
    retirement=loads(read(folder/"RETIREMENT.json"));last={r["case"]:r["after"] for r in observations}
    require(retirement["owned_root"]==metadata["owned_fixture"] and retirement["removed_after_capture"] is True and
            len(retirement["complete_final_observations"])==len(domain),"complete original retirement")
    require(all(complete(retirement["complete_final_observations"][i])==complete(last[i]) for i in range(len(domain))),"every final original file retained")
    for key,name in (("process","process.json"),("observations","OBSERVATIONS.json"),("retirement","RETIREMENT.json")):require(report[key]==pin(read(folder/name)),"original exact report file")
    return dict(status="COMPLETE_PINNED_ANCHOR_ORIGINAL_READBACK_PASS",cases=len(domain),operations=index,original_errors=len(errors),
                complete_stdout=pin(bytes(stdout)),complete_stderr=pin(read(folder/"original.stderr")),filesystem_equal=True,
                complete_original_error_diagnostics=errors,exact_serde_error_text_compared=False,native_or_rust_executions=0,reader_writes=0)
