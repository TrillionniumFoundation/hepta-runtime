"""Owned real Linux fixtures and complete observations; no result prediction."""
from pathlib import Path
import hashlib,os,shutil,stat,struct,tempfile,time
from evidence_common import require,sha
from protocol import stat_value,exception
def attributes(path):
    return [dict(name_hex=os.fsencode(n).hex(),value_hex=os.getxattr(path,n).hex())for n in os.listxattr(path)]
def observe(path,follow=False):
    path=Path(path)
    try:st=path.stat()if follow else path.lstat()
    except OSError as e:return dict(exists=False,error=exception(e))
    kind="regular"if stat.S_ISREG(st.st_mode)else"directory"if stat.S_ISDIR(st.st_mode)else"fifo"if stat.S_ISFIFO(st.st_mode)else"other"
    row=dict(exists=True,kind=kind,stat=stat_value(st))
    try:row["attributes"]=attributes(path)
    except OSError as e:row["attribute_error"]=exception(e)
    if kind=="regular":
        raw=path.read_bytes();row["content"]=dict(bytes=len(raw),sha256=sha(raw),hex=raw.hex())
    return row
class Fixture:
    def __init__(self,query):
        self.query=query;self.roots={};self.paths={};self.owned=[];self.setup=[]
        for label,parent in(("runner-temp",os.environ["RUNNER_TEMP"]),("existing-shm","/dev/shm")):
            self.roots[label]=Path(tempfile.mkdtemp(prefix="hia-metadata-%03d-"%query["id"],dir=parent))
        try:
            for role in("source","target"):
                if role=="target"and query.get("target_is_source"):self.paths[role]=self.paths["source"];continue
                spec=query[role]
                if spec["kind"]=="preexisting":
                    path=Path(spec["path"]);before=observe(path)
                    require(before["exists"]and before["kind"]=="regular"and before["stat"]["st_uid"]==spec["require_uid"]
                        and before["stat"]["st_nlink"]==spec["require_nlink"],"declared preexisting readonly fixture")
                    attrs={r["name_hex"]:r["value_hex"]for r in before["attributes"]};cap=b"security.capability".hex()
                    if spec.get("require_no_capability"):require(cap not in attrs,"unexpected existing capability")
                    if "require_capability_hex"in spec:require(attrs.get(cap)==spec["require_capability_hex"],"actual capability input changed")
                    self.paths[role]=path;self.setup.append(dict(role=role,preexisting_readonly=True,actual=before));continue
                path=self.roots[spec.get("filesystem",query["filesystem"])]/role;self.paths[role]=path;self.owned.append(path)
                if spec["kind"]=="regular":path.write_bytes(bytes.fromhex(spec["content_hex"]))
                elif spec["kind"]=="directory":path.mkdir()
                elif spec["kind"]=="fifo":os.mkfifo(path,0o600)
                else:raise ValueError("unknown owned fixture kind")
                if "gid"in spec:require(spec["gid"]in os.getgroups(),"fixture group not already held");os.chown(path,-1,spec["gid"])
                for row in spec.get("attributes",[]):os.setxattr(path,bytes.fromhex(row["name_hex"]),bytes.fromhex(row["value_hex"]))
                if spec.get("acl"):
                    entries=[(1,6,0xffffffff)]
                    if spec["acl"]=="named-user":entries.append((2,4,(os.geteuid()+1)&0xffffffff))
                    entries.append((4,4,0xffffffff))
                    if spec["acl"]=="named-group":entries.append((8,4,4))
                    entries += [(16,4,0xffffffff),(32,0,0xffffffff)]
                    value=struct.pack("<I",2)+b"".join(struct.pack("<HHI",*r)for r in entries)
                    os.setxattr(path,b"system.posix_acl_access",value)
                os.chmod(path,spec["mode"])
                for index in range(1,spec.get("links",1)):os.link(path,path.with_name(role+"-link-"+str(index)))
                self.setup.append(dict(role=role,preexisting_readonly=False,actual=observe(path)))
        except BaseException:self.cleanup();raise
    def all(self,pid=None,fds=None):
        roots={}
        for label,root in self.roots.items():
            roots[label]={p.relative_to(root).as_posix():observe(p)for p in sorted(root.rglob("*"))}
        roles={r:observe(p)for r,p in self.paths.items()}
        held={}
        if pid is not None:
            for role,fd in(fds or{}).items():held[role]=observe(Path("/proc")/str(pid)/"fd"/str(fd),follow=True)
        return dict(roots=roots,roles=roles,held=held)
    def prepare_held(self):
        if self.query.get("unlink_source_before"):os.unlink(self.paths["source"])
    def effect(self,action):
        role=action["role"];path=self.paths[role]
        require(path in self.owned,"mutation only selects a declared owned fixture")
        kind=action["effect"];time.sleep(.002)
        if kind in("append","overwrite"):
            with path.open("ab"if kind=="append"else"r+b")as out:
                raw=bytes.fromhex(action["bytes_hex"]);require(out.write(raw)==len(raw),"complete fixture mutation")
        elif kind=="set-xattr":os.setxattr(path,bytes.fromhex(action["name_hex"]),bytes.fromhex(action["value_hex"]))
        elif kind=="remove-xattr":os.removexattr(path,bytes.fromhex(action["name_hex"]))
        elif kind=="chmod":os.chmod(path,action["mode"])
        elif kind=="utime":os.utime(path,ns=(path.stat().st_atime_ns,action["mtime_ns"]))
        elif kind=="hardlink":os.link(path,path.with_name(role+"-actor-link"))
        elif kind=="unlink":os.unlink(path)
        elif kind=="chgrp":
            require(action["gid"]in os.getgroups(),"actor group is not already held");os.chown(path,-1,action["gid"])
        else:raise ValueError("unknown frozen fixture action")
    def cleanup(self):
        for root in self.roots.values():
            if root.exists():shutil.rmtree(root)
