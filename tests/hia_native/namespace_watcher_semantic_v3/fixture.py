"""Owned complete physical trees; one mutation precedes all three real observers."""
import os,shutil,stat
from pathlib import Path
from common import pin,require
def component(raw):
    value=bytes.fromhex(raw)
    require(b"/"not in value and b"\0"not in value and value not in(b".",b".."),"owned single path component")
    return value
def root_path(folder,case,index):
    require(type(index)is int and 0<=index<len(case["roots"]),"frozen owned root index")
    name=case["roots"][index]["name"].encode()
    require(name and b"/"not in name and b"\0"not in name and name not in(b".",b".."),"owned root basename")
    return os.fsencode(folder)+b"/"+name
def setup(folder,case):
    require(not folder.exists()and not folder.is_symlink(),"new exact owned fixture")
    folder.mkdir(mode=0o700);seen={}
    for index,row in enumerate(case["roots"]):
        path=root_path(folder,case,index)
        if path in seen:
            require(seen[path]==row["kind"],"same duplicate root kind");continue
        seen[path]=row["kind"]
        if row["kind"]=="directory":os.mkdir(path,0o700)
        elif row["kind"]=="file":
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
            try:require(os.write(fd,b"borrowed regular file")==21,"entire owned regular file")
            finally:os.close(fd)
        else:raise ValueError("unlisted original root kind")
def write(path,raw,create):
    flags=os.O_WRONLY|os.O_CLOEXEC|(os.O_CREAT|os.O_EXCL if create else os.O_TRUNC)
    fd=os.open(path,flags,0o600)
    try:
        at=0
        while at<len(raw):
            n=os.write(fd,raw[at:]);require(n>0,"complete actual fixture write");at+=n
    finally:os.close(fd)
def apply(folder,case,rows):
    for row in rows:
        root=root_path(folder,case,row["root"]);op=row["op"]
        name=component(row.get("path_hex",""));path=root+(b"/"+name if name else b"")
        if op=="file":require(name,"file basename");write(path,bytes.fromhex(row["data_hex"]),True)
        elif op=="write":require(name,"rewrite basename");write(path,bytes.fromhex(row["data_hex"]),False)
        elif op=="chmod":os.chmod(path,row["mode"],follow_symlinks=False)
        elif op=="rename":
            target=component(row["to_hex"]);require(name and target,"same-directory rename")
            os.rename(path,root+b"/"+target)
        elif op=="unlink":
            if row.get("directory"):os.rmdir(path)
            else:require(name,"file unlink basename");os.unlink(path)
        elif op=="mkdir-root":require(not name,"exact root recreation");os.mkdir(root,0o700)
        elif op=="rename-root":
            to=row["to"].encode();require(to and b"/"not in to and to not in(b".",b".."),"root rename basename")
            os.rename(root,os.fsencode(folder)+b"/"+to)
        else:raise ValueError("unlisted frozen filesystem mutation")
def snapshot(root):
    result=[]
    def visit(path,relative):
        info=os.lstat(path);mode=info.st_mode
        row=dict(path_hex=relative.hex(),mode=stat.S_IMODE(mode),type=stat.S_IFMT(mode),device=info.st_dev,
            inode=info.st_ino,nlink=info.st_nlink,uid=info.st_uid,gid=info.st_gid,size=info.st_size,
            mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
        if stat.S_ISREG(mode):
            with open(path,"rb")as stream:raw=stream.read()
            row.update(content_hex=raw.hex(),content=pin(raw))
        elif stat.S_ISLNK(mode):row["target_hex"]=os.readlink(path).hex()
        result.append(row)
        if stat.S_ISDIR(mode):
            try:names=sorted(os.listdir(path))
            except OSError as error:row["scan_errno"]=error.errno;return
            for name in names:visit(path+b"/"+name,relative+(b"/"if relative else b"")+name)
    try:visit(os.fsencode(root),b"")
    except FileNotFoundError:return dict(exists=False,entries=[])
    return dict(exists=True,entries=result)
def retire(root,observed):
    require(snapshot(root)==observed,"entire exact tree before explicit retirement")
    require(root.is_dir()and not root.is_symlink(),"owned retirement directory")
    shutil.rmtree(root)
    require(not root.exists()and not root.is_symlink(),"only exact owned fixture retired")
    return dict(complete_before=observed,retired=True,root=str(root))
