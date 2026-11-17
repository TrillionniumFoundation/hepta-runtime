"""Owned fixtures and complete bytes observed through independent held read descriptors."""
import hashlib,os,stat,shutil
from pathlib import Path
from common import require
NAME=".request-archive-v11-anchor.json"
READERS={}
def remember(fd):
    info=os.fstat(fd);key=(info.st_dev,info.st_ino)
    if key not in READERS:READERS[key]=os.dup(fd)
def write_file(path,raw,mode=0o600):
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    try:
        at=0
        while at<len(raw):
            n=os.write(fd,raw[at:]);require(n>0,"complete owned setup write");at+=n
        remember(fd);os.fchmod(fd,mode)
    finally:os.close(fd)
def setup(root,rows):
    require(not READERS,"no previous fixture descriptor")
    root.mkdir(parents=True,exist_ok=False);root.chmod(0o700)
    for ci,row in enumerate(rows):
        folder=root/("case-%04d"%ci);folder.mkdir(mode=0o700);folder.chmod(0o700)
        p=folder/NAME;kind=row["kind"];raw=bytes.fromhex(row["data_hex"])
        if kind in ("file","hardlink"):write_file(p,raw,row["mode"])
        if kind=="hardlink":os.link(p,folder/"second-link",follow_symlinks=False)
        if kind=="directory":p.mkdir(mode=0o700);p.chmod(0o700)
        if kind=="fifo":os.mkfifo(p,0o600)
        if kind=="symlink":
            write_file(folder/"target",raw,0o600);os.symlink("target",p)
        require(kind in ("file","hardlink","directory","fifo","symlink","missing"),"fixed fixture kind")
    return root
def apply(folder,actions):
    p=folder/NAME
    for action in actions:
        typ=action["type"]
        if typ=="chmod":os.chmod(p,action["mode"])
        elif typ=="write":
            raw=bytes.fromhex(action["data_hex"]);fd=os.open(p,os.O_WRONLY|os.O_CLOEXEC)
            try:
                os.ftruncate(fd,0);at=0
                while at<len(raw):
                    n=os.write(fd,raw[at:]);require(n>0,"complete external write");at+=n
            finally:os.close(fd)
        elif typ=="mtime":
            st=os.stat(p,follow_symlinks=False);os.utime(p,ns=(st.st_atime_ns,st.st_mtime_ns+action["delta"]),follow_symlinks=False)
        elif typ=="unlink":os.unlink(p)
        elif typ=="replace":
            temp=folder/"fixture-replacement";write_file(temp,bytes.fromhex(action["data_hex"]),action["mode"]);os.replace(temp,p)
        elif typ=="link":os.link(p,folder/"additional-link",follow_symlinks=False)
        elif typ=="rename":os.rename(p,folder/"renamed-anchor")
        elif typ=="read":
            fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC)
            try:
                while os.read(fd,65536):pass
            finally:os.close(fd)
        elif typ=="unrelated":write_file(folder/"unrelated",bytes.fromhex(action["data_hex"]),0o600)
        else:raise ValueError("unexpected fixture action")
def metadata(st):
    return {k:getattr(st,k) for k in ("st_mode","st_uid","st_gid","st_nlink","st_size","st_dev","st_ino","st_atime_ns","st_mtime_ns","st_ctime_ns")}
def snapshot(folder):
    rows=[]
    def visit(path,relative):
        st=os.lstat(path);row=dict(path_hex=os.fsencode(relative).hex(),stat=metadata(st))
        if stat.S_ISREG(st.st_mode):
            key=(st.st_dev,st.st_ino);require(key in READERS,"retained independent readable fixture inode")
            fd=READERS[key];opened=os.fstat(fd)
            require((opened.st_dev,opened.st_ino)==key,"exact observed descriptor")
            chunks=[];at=0
            while True:
                raw=os.pread(fd,65536,at)
                if not raw:break
                chunks.append(raw);at+=len(raw)
            raw=b"".join(chunks);after=os.fstat(fd)
            require((opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==st.st_size,"stable complete file")
            row.update(kind="file",data_hex=raw.hex(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        elif stat.S_ISDIR(st.st_mode):row["kind"]="directory"
        elif stat.S_ISLNK(st.st_mode):row.update(kind="symlink",target_hex=os.fsencode(os.readlink(path)).hex())
        elif stat.S_ISFIFO(st.st_mode):row["kind"]="fifo"
        else:raise ValueError("owned fixture type")
        rows.append(row)
        if row["kind"]=="directory":
            for name in sorted(os.listdir(path)):visit(path/name,relative+("/" if relative else "")+name)
    visit(Path(folder),"");return rows
def normalized(rows):
    groups={}
    for row in rows:
        if row["kind"]=="file":groups.setdefault((row["stat"]["st_dev"],row["stat"]["st_ino"]),[]).append(row["path_hex"])
    result=[]
    for row in rows:
        st=row["stat"];v=dict(path_hex=row["path_hex"],kind=row["kind"],mode=st["st_mode"],uid=st["st_uid"],gid=st["st_gid"],nlink=st["st_nlink"])
        if row["kind"]=="file":
            raw=bytes.fromhex(row["data_hex"]);require(len(raw)==row["bytes"]==st["st_size"] and hashlib.sha256(raw).hexdigest()==row["sha256"],"every full observed file")
            v.update(data_hex=row["data_hex"],size=st["st_size"],hardlinks=sorted(groups[(st["st_dev"],st["st_ino"])]))
        if row["kind"]=="symlink":v["target_hex"]=row["target_hex"]
        result.append(v)
    return result
def retire(root,rows):
    final=[snapshot(root/("case-%04d"%ci)) for ci in range(len(rows))]
    st=root.lstat()
    close_error=None
    try:
        for fd in list(READERS.values()):
            try:os.close(fd)
            except BaseException as error:
                if close_error is None:close_error=error
    finally:READERS.clear()
    if close_error is not None:raise close_error
    shutil.rmtree(root);require(not root.exists(),"owned fixture retired after native/original exit")
    return dict(owned_root=str(root),device=st.st_dev,inode=st.st_ino,complete_final_observations=final,removed_after_capture=True)
