"""Owned corpus actions and complete physical snapshots outside all three implementations."""
import hashlib,os,shutil,socket,stat
from pathlib import Path
from common import require,pin,encoded
def component(raw):
    require(type(raw)is str,"hex component")
    path=bytes.fromhex(raw);require(path.hex()==raw and b"\0" not in path and b"/" not in path and path not in(b".",b".."),"owned single raw component")
    return path
def action(root,row):
    name=component(row["path_hex"]);path=os.fsencode(root)+(b"/"+name if name else b"")
    op=row["op"]
    if op=="file":
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_CLOEXEC,0o600)
        try:
            raw=bytes.fromhex(row.get("data_hex",""));at=0
            while at<len(raw):
                n=os.write(fd,raw[at:]);require(n>0,"complete fixture write");at+=n
        finally:os.close(fd)
    elif op=="write":
        fd=os.open(path,os.O_WRONLY|os.O_TRUNC|os.O_CLOEXEC)
        try:
            raw=bytes.fromhex(row["data_hex"]);at=0
            while at<len(raw):
                n=os.write(fd,raw[at:]);require(n>0,"complete fixture rewrite");at+=n
        finally:os.close(fd)
    elif op=="directory":os.mkdir(path,0o700)
    elif op=="fifo":os.mkfifo(path,0o600)
    elif op=="symlink":os.symlink(bytes.fromhex(row["target_hex"]),path)
    elif op=="hardlink":os.link(os.fsencode(root)+b"/"+component(row["from_hex"]),path,follow_symlinks=False)
    elif op=="socket":
        sock=socket.socket(socket.AF_UNIX)
        try:sock.bind(path)
        finally:sock.close()
    elif op=="rename":os.rename(path,os.fsencode(root)+b"/"+component(row["to_hex"]))
    elif op=="unlink":
        if row.get("directory"):os.rmdir(path)
        else:os.unlink(path)
    elif op=="chmod":os.chmod(path,row["mode"],follow_symlinks=False)
    elif op=="remove_root":require(not name,"exact owned root removal");os.rmdir(path)
    else:raise ValueError("unlisted fixture action")
def apply(root,rows):
    for row in rows:action(root,row)
def setup(folder,case):
    require(not folder.exists() and not folder.is_symlink(),"new exact fixture root")
    if case["root_kind"]=="directory":folder.mkdir(mode=0o700)
    elif case["root_kind"]=="file":folder.write_bytes(b"borrowed regular file")
    else:raise ValueError("root kind")
    apply(folder,case["setup"])
def snapshot(root):
    rawroot=os.fsencode(root);result=[]
    def visit(path,relative):
        info=os.lstat(path);mode=info.st_mode
        row=dict(path_hex=relative.hex(),mode=stat.S_IMODE(mode),type=stat.S_IFMT(mode),
                 device=info.st_dev,inode=info.st_ino,nlink=info.st_nlink,uid=info.st_uid,gid=info.st_gid,
                 size=info.st_size,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
        if stat.S_ISREG(mode):
            with open(path,"rb")as stream:raw=stream.read()
            row.update(content_hex=raw.hex(),content=pin(raw))
        elif stat.S_ISLNK(mode):row["target_hex"]=os.readlink(path).hex()
        result.append(row)
        if stat.S_ISDIR(mode):
            try:names=sorted(os.listdir(path))
            except OSError as failure:row["scan_errno"]=failure.errno;return
            for name in names:visit(path+b"/"+name,relative+(b"/"if relative else b"")+name)
    try:visit(rawroot,b"")
    except FileNotFoundError:return dict(exists=False,entries=[])
    return dict(exists=True,entries=result)
def retire(root,observed):
    require(snapshot(root)==observed,"exact owned fixture before retirement")
    if root.exists():
        if root.is_dir():os.chmod(root,0o700);shutil.rmtree(root)
        else:root.unlink()
    require(not root.exists()and not root.is_symlink(),"retired exact fixture root")
    return dict(complete_before=observed,retired=True,root=str(root))
