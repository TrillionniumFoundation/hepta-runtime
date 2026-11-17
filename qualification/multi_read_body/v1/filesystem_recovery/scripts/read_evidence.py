"""Complete process streams, acquisition index, concrete files and original provenance."""
from pathlib import Path
import ast,gzip,hashlib,json,stat
from evidence_common import decode,encoded,pin,require,sha
from buffer_store import Reader
from protocol import U
def walk(value,reader):
    if isinstance(value,dict):
        if set(value)=={"bytes","sha256","blocks"}:reader.get(value)
        else:
            for v in value.values():walk(v,reader)
    elif isinstance(value,list):
        for v in value:walk(v,reader)
def rows(folder,report):
    path=folder/"cases.jsonl.gz";require(pin(path)==report["cases_file"],"complete case archive identity")
    values=[];digest=hashlib.sha256();size=0
    with gzip.open(path,"rb")as stream:
        for raw in stream:
            require(raw.endswith(b"\n")and len(raw)<=256<<20,"complete case row")
            v=decode(raw);expected=report["case_rows"][len(values)]
            require(expected==dict(id=v["input"]["id"],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),"whole case row hash")
            digest.update(raw);size+=len(raw);values.append(v)
    require(dict(bytes=size,sha256=digest.hexdigest())==report["cases_raw"]and len(values)==report["cases"],"complete cases stream")
    return values
def stream_custody(folder,receipt,exchanges,reader):
    require(receipt["returncode"]==0 and receipt["same_outer_process_group"]is True
        and receipt["parent_pgid"]==receipt["child_pgid"]and receipt["fixed_journal_fd"]==3
        and receipt["fixed_notify_fd"]==4 and receipt["fixed_ack_fd"]==5 and receipt["elapsed_ns"]<=180000000000,
        "natural bounded actual process custody")
    for n in("stdin","stderr"):require(pin(folder/("carrier."+n))==receipt["streams"][n],"full actual stream")
    require((folder/"carrier.stderr").read_bytes()==b"","actual process stderr")
    require(pin(folder/"carrier.stdout.gz")==receipt["stdout"]["compressed"],"complete stdout compressed identity")
    digest=hashlib.sha256();size=0;last=0
    with (folder/"carrier.stdin").open("rb")as inp,gzip.open(folder/"carrier.stdout.gz","rb")as out:
        for index,r in enumerate(exchanges,1):
            require(r["exchange"]==index and 0<=r["elapsed_ns"]<=60000000000,"ordered full exchange/budget")
            a=reader.get(r["input"]);b=reader.get(r["output"])
            require(inp.read(len(a))==a and out.read(len(b))==b,"whole process stream/buffer equality")
            digest.update(b);size+=len(b)
            require(len(a)>=72 and U(a,0)==len(a)-8 and a[8:16]==b"HMRDFQ01"
                and U(a,16)==r["command"]in range(1,26)and U(a,24)==r["session"]in(0,1)
                and U(a,32)==len(a)-72 and a[40:72]==bytes(32),"fixed complete fixture input")
            require(len(b)>=64 and b[:8]==b"HMRDFR01"and U(b,16)==len(b)-64,"fixed complete fixture output")
            require(r["journal_begin"]==last<=r["journal_end"],"complete contiguous journal")
            if r["command"]not in(1,13):require(r["journal_begin"]==r["journal_end"],"unexpected fixture semantic call")
            last=r["journal_end"]
        require(not inp.read(1)and not out.read(1),"unread complete process suffix")
    require(dict(bytes=size,sha256=digest.hexdigest())==receipt["stdout"]["raw"]and last==receipt["journal"]["raw"]["bytes"],"whole stdout/journal extent")

def open_buffers(folder,report):
    path=folder/"buffer-index.jsonl";require(pin(path)==report["buffer_index"],"complete acquisition index")
    index=[decode(raw)for raw in path.read_bytes().splitlines()]
    require(len(index)==report["buffers"]["images"] and sum(x["bytes"]for x in index)==report["buffers"]["logical_bytes"],
        "all full acquired buffers")
    reader=Reader(folder/"buffers");get=reader.get;allowed={encoded(x)for x in index}
    for row in index:get(row)
    def checked(row):
        require(encoded(row)in allowed,"buffer was never acquired");return get(row)
    reader.get=checked
    return reader,dict(images=len(index),logical_bytes=sum(x["bytes"]for x in index))
def reference_binding(source):
    def asts(path,names):
        nodes={n.name:n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef)}
        return {name:sha(ast.dump(nodes[name],include_attributes=False).encode())for name in names}
    binary=source/"target/binary_file.py";multi=source/"target/multi_read_host.py"
    return dict(binary=pin(binary),multi=pin(multi),metadata=pin(source/"target/file_metadata.py"),
        binary_functions=asts(binary,("parent","regular","version")),
        multi_functions=asts(multi,("_batch_path","_wire_size","multi_read","run_multi_read")),
        original_functions_unmodified=True,observation_only_at_real_os_boundary=True)
def references(value):
    out=[]
    if isinstance(value,dict):
        for k,v in value.items():
            if(k=="exchange"or k.endswith("_exchange"))and type(v)is int:out.append(v)
            else:out+=references(v)
    elif isinstance(value,list):
        for v in value:out+=references(v)
    return out
def file_snapshot(value):
    require(type(value["root"])is str and value["held"]=={} and "."in value["entries"],"complete owned fixture")
    for name,row in value["entries"].items():
        require(name=="."or(not name.startswith("/")and ".."not in Path(name).parts),"owned snapshot path")
        if not row["exists"]:continue
        mode=row["stat"]["st_mode"]
        expected="regular"if stat.S_ISREG(mode)else"directory"if stat.S_ISDIR(mode)else"symlink"if stat.S_ISLNK(mode)else"fifo"if stat.S_ISFIFO(mode)else"other"
        require(row["kind"]==expected,"actual file type")
        if "content"in row:
            raw=bytes.fromhex(row["content"]["hex"])
            require(row["content"]["bytes"]==len(raw) and row["content"]["sha256"]==sha(raw)
                and row["stat"]["st_size"]==len(raw),"whole actual file content")
        for item in row.get("attributes",[]):
            bytes.fromhex(item["name_hex"]);bytes.fromhex(item["value_hex"])
def setup(case):
    q=case["input"];root=Path(case["fixture_root"]);snapshot=case["setup"];file_snapshot(snapshot)
    require(root.name.startswith("hia-multi-fs-%03d-"%q["id"]) and snapshot["root"]==str(root)
        and case["initial_parent"]==str(root/"parent"),"owned setup root")
    entries=snapshot["entries"];expected={".","parent","parent/replacement.txt"}
    replacement=entries["parent/replacement.txt"]
    require(replacement["content"]["hex"]==b"precreated replacement inode\n".hex()
        and replacement["stat"]["st_mode"]&0o7777==0o600,"precreated distinct replacement")
    for spec in q["files"]:
        p=Path(spec["path"])
        for parent in p.parents:
            if str(parent)!=".":expected.add(parent.as_posix())
        if spec["kind"]=="missing":require(spec["path"]not in entries,"fixed missing input");continue
        expected.add(spec["path"]);row=entries[spec["path"]]
        require(row["exists"]and row["kind"]==spec["kind"],"exact input file kind")
        if spec["kind"]=="symlink":require(row["link"]==spec["target"],"exact link input")
        else:
            require(row["stat"]["st_mode"]&0o7777==spec["mode"],"exact input mode")
            if spec["kind"]=="regular":
                require(row["stat"]["st_size"]==len(bytes.fromhex(spec["content_hex"]))
                    and row["stat"]["st_nlink"]==spec["links"],"exact input size/link count")
                if "content"in row:require(row["content"]["hex"]==spec["content_hex"],"actual input bytes")
                else:require(spec["mode"]==0 and row["content_error"]["errno"]==13,"explicit inaccessible fixture")
            for n in range(1,spec["links"]):
                name=p.with_name(p.name+".initial-link-"+str(n)).as_posix();expected.add(name)
                require(entries[name]["stat"]["st_ino"]==row["stat"]["st_ino"]
                    and entries[name]["stat"]["st_dev"]==row["stat"]["st_dev"],"actual hardlink alias")
    require(set(entries)==expected,"complete setup file set")
def hooks(case,reader):
    q=case["input"];value=case["actual"]["hooks"]
    require(value["replacements_of_native_result"]==0 and value["ack_is_only_eight_zero_bytes"]is True
        and value["actual_actor_count"]==len(q["actions"])==len(value["actions"]),"fixed observational effects")
    from read_trace import HOOK
    result=[];counts={};last_attempt=None
    for row in value["events"]:
        owner=row["owner"];raw=reader.get(row["raw"]);ack=reader.get(row["ack"])
        require(owner in HOOK and raw==HOOK[owner]+__import__("struct").pack("<7Q",
            row["generation"],row["call"],row["sequence"],row["operation"],row["fd"],row["a"],row["b"])
            and ack==bytes(8),"whole notification bytes")
        if last_attempt!=row["attempt"]:counts={};last_attempt=row["attempt"]
        key=(owner,row["operation"]);counts[key]=counts.get(key,0)+1
        require(row["occurrence"]==counts[key]and 1<=row["attempt"]<=q["attempts"],"actual before-effect ordinal")
        for action in row["actions"]:
            index=action["index"];require(q["actions"][index]==action["input"]and action in value["actions"]
                and action["attempt"]==row["attempt"]and action["actor_pid"]!=action["target_pid"]
                and action["target_pid"]==case["process"]["pid"],"separate exact filesystem actor")
            file_snapshot(action["before"]);file_snapshot(action["after"])
        result.append(dict(row,raw_bytes=raw,ack_bytes=ack))
    require(len(value["eof"])==1,"actual process reaches a complete pre-exit witness")
    e=value["eof"][0];raw=reader.get(e["raw"]);require(len(raw)==64 and raw[:8]==b"HMRDEOF1"
        and raw[24:]==bytes(40)and reader.get(e["ack"])==bytes(8),"fixed EOF bytes")
    if not q["observer"]:require(not result,"observer-off has no hidden journal")
    require(len(value["limits"])==(q["attempts"]if q["fd_free"]is not None else 0),"all real limits")
    for l in value["limits"]:
        fds=sorted(map(int,l["fds"]));require(fds==list(range(max(fds)+1))
            and l["exactly_free_fds"]==list(range(max(fds)+1,l["during"][0]))
            and len(l["exactly_free_fds"])==q["fd_free"]and l["after"]==l["before"]
            and l["during"][1]==l["before"][1],"actual limit and restoration")
    return result
def original_journal(folder,receipt,events):
    require(pin(folder/"carrier.journal.gz")==receipt["compressed"],"complete original journal archive")
    digest=hashlib.sha256();size=0;rows=[]
    with gzip.open(folder/"carrier.journal.gz","rb")as stream:
        for raw in stream:
            require(raw.endswith(b"\n"),"whole original operation row")
            digest.update(raw);size+=len(raw);rows.append(decode(raw))
    require(dict(bytes=size,sha256=digest.hexdigest())==receipt["raw"]and len(rows)==len(events),
        "every original real operation retained")
    for row,event in zip(rows,events):
        require(all(row[k]==event[k]for k in("owner","generation","call","operation","fd")),"real original effect/barrier binding")
        row["hook"]=event
    return rows
