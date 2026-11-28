"""Owned complete filesystem snapshots, including generated temporary names."""
import hashlib,os,re,shutil,stat
from pathlib import Path
from common import require
NAME=".request-archive-v11-anchor.json"
READERS={}
def remember(fd):
    st=os.fstat(fd);key=(st.st_dev,st.st_ino)
    if key not in READERS:READERS[key]=os.dup(fd)
def write_file(path,raw,mode=0o600):
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    try:
        at=0
        while at<len(raw):
            n=os.write(fd,raw[at:]);require(n>0,"full owned setup");at+=n
        remember(fd);os.fchmod(fd,mode)
    finally:os.close(fd)
def setup(root,rows):
    require(not READERS,"fresh fixture descriptors")
    root.mkdir(parents=True,exist_ok=False);root.chmod(0o700)
    for ci,row in rows:
        folder=root/("case-%04d"%ci)
        if row["root_kind"]=="file":
            write_file(folder,b"borrowed-root-file",0o600);continue
        require(row["root_kind"]=="directory","known root type")
        folder.mkdir(mode=0o700);p=folder/NAME;kind=row["kind"];raw=bytes.fromhex(row["data_hex"])
        if kind in ("file","hardlink"):write_file(p,raw,row["mode"])
        if kind=="hardlink":os.link(p,folder/"second-link",follow_symlinks=False)
        if kind=="directory":p.mkdir(mode=0o700);p.chmod(0o700)
        if kind=="fifo":os.mkfifo(p,0o600)
        if kind=="symlink":
            write_file(folder/"target",raw);os.symlink("target",p)
        require(kind in ("file","hardlink","directory","fifo","symlink","missing"),"complete fixture kinds")
        folder.chmod(row["root_mode"])
    return root
def apply(folder,actions):
    for action in actions:
        require(action=={"type":"unlink_anchor"},"fixed external interturn action")
        os.unlink(folder/NAME)
def metadata(st):
    return {k:getattr(st,k) for k in ("st_mode","st_uid","st_gid","st_nlink","st_size","st_dev","st_ino","st_atime_ns","st_mtime_ns","st_ctime_ns")}
def snapshot(folder):
    rows=[]
    def visit(path,relative):
        st=os.lstat(path);row=dict(path_hex=os.fsencode(relative).hex(),stat=metadata(st))
        if stat.S_ISREG(st.st_mode):
            key=(st.st_dev,st.st_ino)
            if key not in READERS:
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:remember(fd)
                finally:os.close(fd)
            fd=READERS[key];before=os.fstat(fd);parts=[];at=0
            require((before.st_dev,before.st_ino)==key,"held complete file")
            while True:
                raw=os.pread(fd,65536,at)
                if not raw:break
                parts.append(raw);at+=len(raw)
            raw=b"".join(parts);after=os.fstat(fd)
            require((before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                    (after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==st.st_size,
                    "stable full owned bytes")
            row.update(kind="file",data_hex=raw.hex(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        elif stat.S_ISDIR(st.st_mode):row["kind"]="directory"
        elif stat.S_ISLNK(st.st_mode):row.update(kind="symlink",target_hex=os.fsencode(os.readlink(path)).hex())
        elif stat.S_ISFIFO(st.st_mode):row["kind"]="fifo"
        else:raise ValueError("unexpected owned type")
        rows.append(row)
        if row["kind"]=="directory":
            for name in sorted(os.listdir(path)):visit(path/name,relative+("/" if relative else "")+name)
    visit(Path(folder),"");return rows
def normalized(rows,temporaries=()):
    names={name.encode().hex():("@entropy-temporary-%04d"%i).encode().hex() for i,name in enumerate(temporaries)}
    require(len(names)==len(temporaries),"unique actual entropy names in this fixed cohort")
    groups={}
    for row in rows:
        if row["kind"]=="file":
            groups.setdefault((row["stat"]["st_dev"],row["stat"]["st_ino"]),[]).append(names.get(row["path_hex"],row["path_hex"]))
    result=[]
    for row in rows:
        st=row["stat"];p=bytes.fromhex(row["path_hex"])
        if re.fullmatch(rb"\.archive-anchor-[0-9a-f]{64}\.tmp",p):
            require(row["path_hex"] in names,"every generated pathname tied to actual entropy/open")
        v=dict(path_hex=names.get(row["path_hex"],row["path_hex"]),kind=row["kind"],
               mode=st["st_mode"],uid=st["st_uid"],gid=st["st_gid"],nlink=st["st_nlink"])
        if row["kind"]=="file":
            raw=bytes.fromhex(row["data_hex"])
            require(len(raw)==row["bytes"]==st["st_size"] and hashlib.sha256(raw).hexdigest()==row["sha256"],"entire observed file")
            v.update(data_hex=row["data_hex"],size=st["st_size"],hardlinks=sorted(groups[(st["st_dev"],st["st_ino"])]))
        if row["kind"]=="symlink":v["target_hex"]=row["target_hex"]
        result.append(v)
    return sorted(result,key=lambda r:r["path_hex"])
def finish(root,rows):
    final=[dict(case=ci,rows=snapshot(root/("case-%04d"%ci))) for ci,_ in rows]
    st=root.lstat();error=None
    for fd in list(READERS.values()):
        try:os.close(fd)
        except BaseException as e:
            if error is None:error=e
    READERS.clear()
    if error is not None:raise error
    return dict(owned_root=str(root),device=st.st_dev,inode=st.st_ino,
                complete_final_observations=final,fixture_still_present=True)
def retire(root,receipt):
    require(str(root)==receipt["owned_root"] and root.is_dir() and not root.is_symlink(),"exact owned retirement root")
    st=root.stat();require((st.st_dev,st.st_ino)==(receipt["device"],receipt["inode"]),"same fixture after producer exit")
    # Owner is done; chmod only permits removing an explicitly owned readonly fixture.
    for folder,dirs,names in os.walk(root,followlinks=False):
        os.chmod(folder,0o700)
    shutil.rmtree(root);require(not root.exists(),"exact owned tree retired after child exit")
    return dict(**receipt,removed_after_capture=True)
