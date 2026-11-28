"""Real owned files, exact attributes, and separately owned mutation effects."""
from pathlib import Path
import os,shutil,stat,struct,tempfile,time
from evidence_common import require,sha
from protocol import stat_value,exception,proc_fds
def attributes(path):
    return [dict(name_hex=os.fsencode(n).hex(),value_hex=os.getxattr(path,n).hex())for n in os.listxattr(path)]
def observe(path,follow=False):
    path=Path(path)
    try:st=path.stat()if follow else path.lstat()
    except OSError as e:return dict(exists=False,error=exception(e))
    kind="regular"if stat.S_ISREG(st.st_mode)else"directory"if stat.S_ISDIR(st.st_mode)else"fifo"if stat.S_ISFIFO(st.st_mode)else"symlink"if stat.S_ISLNK(st.st_mode)else"other"
    row=dict(exists=True,kind=kind,stat=stat_value(st))
    if kind=="symlink":row["link"]=os.readlink(path);return row
    try:row["attributes"]=attributes(path)
    except OSError as e:row["attribute_error"]=exception(e)
    if kind=="regular":
        try:
            raw=path.read_bytes();row["content"]=dict(bytes=len(raw),sha256=sha(raw),hex=raw.hex())
        except OSError as e:row["content_error"]=exception(e)
    return row
class Fixture:
    def __init__(self,q):
        self.query=q;parent="/dev/shm"if q["filesystem"]=="existing-shm"else os.environ["RUNNER_TEMP"]
        self.root=Path(tempfile.mkdtemp(prefix="hia-info-%03d-"%q["id"],dir=parent));self.parent=self.root/"parent"
        self.parent.mkdir();self.parent_path=self.parent
        name=q["basename"];self.physical_name=name if name and "\0"not in name and "/"not in name and len(name.encode())<=255 else"data.bin"
        self.target=self.parent/self.physical_name;self.replacement=self.parent/"replacement.bin";self.setup=[]
        try:
            self.replacement.write_bytes(b"replacement inode bytes\n");self.replacement.chmod(0o600)
            spec=q["file"];kind=spec["kind"]
            if kind=="regular":self.target.write_bytes(bytes.fromhex(spec["content_hex"]))
            elif kind=="directory":self.target.mkdir()
            elif kind=="fifo":os.mkfifo(self.target,0o600)
            elif kind=="symlink":os.symlink("replacement.bin",self.target)
            elif kind!="missing":raise ValueError("undeclared fixture kind")
            if kind not in("missing","symlink"):
                for r in spec["attributes"]:os.setxattr(self.target,bytes.fromhex(r["name_hex"]),bytes.fromhex(r["value_hex"]))
                if spec.get("acl"):
                    entries=[(1,6,0xffffffff),(2,4,(os.geteuid()+1)&0xffffffff),(4,4,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)]
                    os.setxattr(self.target,b"system.posix_acl_access",struct.pack("<I",2)+b"".join(struct.pack("<HHI",*r)for r in entries))
                os.chmod(self.target,spec["mode"])
                for i in range(1,spec.get("links",1)):os.link(self.target,self.parent/("initial-link-"+str(i)))
            self.setup=self.all()
        except BaseException:self.cleanup();raise
    def all(self,pid=None,parents=None):
        values={".":observe(self.root)}
        for p in sorted(self.root.rglob("*")):values[p.relative_to(self.root).as_posix()]=observe(p)
        held={}
        if pid is not None:
            for slot,fd in(parents or{}).items():held[str(slot)]=observe(Path("/proc")/str(pid)/"fd"/str(fd),follow=True)
        return dict(root=str(self.root),entries=values,held=held)
    def effect(self,a):
        q=a["effect"];path=self.target;time.sleep(.002)
        if q in("append","overwrite"):
            with path.open("ab"if q=="append"else"r+b")as out:
                data=bytes.fromhex(a["bytes_hex"]);require(out.write(data)==len(data),"full actor write")
        elif q=="truncate":
            with path.open("r+b")as out:out.truncate(a["size"])
        elif q=="chmod":os.chmod(path,a["mode"])
        elif q=="utime":os.utime(path,ns=(path.stat().st_atime_ns,a["mtime_ns"]))
        elif q=="hardlink":os.link(path,self.parent/"actor-link")
        elif q=="unlink":os.unlink(path)
        elif q=="replace":os.replace(self.replacement,path)
        elif q=="set-xattr":os.setxattr(path,bytes.fromhex(a["name_hex"]),bytes.fromhex(a["value_hex"]))
        elif q=="remove-xattr":os.removexattr(path,bytes.fromhex(a["name_hex"]))
        elif q=="rename-parent":
            new=self.root/"moved";self.parent.rename(new);self.parent=new;self.target=new/self.physical_name;self.replacement=new/"replacement.bin"
            self.parent_path.mkdir();(self.parent_path/self.physical_name).write_bytes(b"new unrelated path occupant\n")
        else:raise ValueError("undeclared actor effect")
    def cleanup(self):
        if self.root.exists():shutil.rmtree(self.root)
