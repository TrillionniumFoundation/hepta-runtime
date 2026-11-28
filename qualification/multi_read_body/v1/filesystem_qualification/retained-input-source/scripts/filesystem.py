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
        self.query=q;place="/dev/shm"if q["filesystem"]=="existing-shm"else os.environ["RUNNER_TEMP"]
        self.root=Path(tempfile.mkdtemp(prefix="hia-multi-fs-%03d-"%q["id"],dir=place))
        self.parent=self.root/"parent";self.parent.mkdir();self.parent_path=self.parent
        self.replacement=self.parent/"replacement.txt";self.moved=False;self.setup=None
        try:
            self.replacement.write_bytes(b"precreated replacement inode\n");self.replacement.chmod(0o600)
            for spec in q["files"]:
                p=self.root/spec["path"];require(p.is_relative_to(self.root) and ".."not in p.parts,"owned setup path")
                p.parent.mkdir(parents=True,exist_ok=True);kind=spec["kind"]
                if kind=="regular":p.write_bytes(bytes.fromhex(spec["content_hex"]))
                elif kind=="directory":p.mkdir()
                elif kind=="fifo":os.mkfifo(p,0o600)
                elif kind=="symlink":os.symlink(spec["target"],p)
                elif kind!="missing":raise ValueError("undeclared fixture kind")
                if kind not in("missing","symlink"):
                    p.chmod(spec["mode"])
                    for n in range(1,spec["links"]):os.link(p,p.with_name(p.name+".initial-link-"+str(n)))
            self.setup=self.all()
        except BaseException:self.cleanup();raise
    def all(self,pid=None,parents=None):
        entries={".":observe(self.root)}
        for p in sorted(self.root.rglob("*")):entries[p.relative_to(self.root).as_posix()]=observe(p)
        return dict(root=str(self.root),entries=entries,held={})
    def effect(self,a):
        effect=a["effect"];path=self.root/a["path"]
        require(path.is_relative_to(self.root) and ".."not in path.parts,"actor stays in owned fixture")
        time.sleep(.002)
        if effect in("append","overwrite"):
            with path.open("ab"if effect=="append"else"r+b")as out:
                raw=bytes.fromhex(a["bytes_hex"]);require(out.write(raw)==len(raw),"full actual actor write")
        elif effect=="truncate":
            with path.open("r+b")as out:out.truncate(a["size"])
        elif effect=="chmod":os.chmod(path,a["mode"])
        elif effect=="utime":os.utime(path,ns=(path.stat().st_atime_ns,a["mtime_ns"]))
        elif effect=="hardlink":os.link(path,self.parent/"actor-link")
        elif effect=="unlink":os.unlink(path)
        elif effect=="replace":os.replace(self.replacement,path)
        elif effect=="rename-parent":
            require(not self.moved,"single parent rename");self.parent.rename(self.root/"moved")
            self.parent_path.mkdir();(self.parent_path/"data.txt").write_bytes(b"new unrelated path occupant\n")
            self.moved=True
        else:raise ValueError("undeclared actor effect")
    def cleanup(self):
        if self.root.exists():shutil.rmtree(self.root)
