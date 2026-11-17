"""Rebuild the full owned filesystem domain from inputs, not expected output wires."""
import stat
from reader_common import pin,require,integer
BASE={"path_hex","mode","type","device","inode","nlink","uid","gid","size","mtime_ns","ctime_ns"}
class Tree:
    def __init__(self,case,uid,gid):
        self.case=case;self.uid=uid;self.gid=gid
        self.nodes={b"":self.node(0o040000,0o700)}
        for row in case["roots"]:
            name=row["name"].encode()
            require(name and b"/"not in name and b"\0"not in name,"source-defined ordinary root component")
            value=self.node(0o040000,0o700)if row["kind"]=="directory"else self.node(0o100000,0o600,b"borrowed regular file")
            if name in self.nodes:require(self.nodes[name]["type"]==value["type"],"same duplicate input root")
            else:self.nodes[name]=value
    def node(self,kind,mode,body=None):
        return dict(type=kind,mode=mode,body=body,observed=None,dirty=set())
    def root(self,index):
        require(type(index)is int and 0<=index<len(self.case["roots"]),"frozen root index")
        return self.case["roots"][index]["name"].encode()
    def dirty(self,path,fields):
        require(path in self.nodes,"actual parent exists")
        self.nodes[path]["dirty"].update(fields)
    def parent(self,path):return path.rsplit(b"/",1)[0]if b"/"in path else b""
    def mutate(self,actions):
        for a in actions:
            root=self.root(a["root"]);name=bytes.fromhex(a.get("path_hex",""))
            require(b"/"not in name and b"\0"not in name and name not in(b".",b".."),"full source byte component")
            path=root+(b"/"+name if name else b"");op=a["op"]
            if op=="file":
                require(path not in self.nodes and name,"new exact source file")
                self.nodes[path]=self.node(0o100000,0o600,bytes.fromhex(a["data_hex"]))
                self.dirty(self.parent(path),{"mtime_ns","ctime_ns","size","nlink"})
            elif op=="write":
                require(self.nodes[path]["type"]==0o100000,"same source regular file")
                self.nodes[path]["body"]=bytes.fromhex(a["data_hex"]);self.dirty(path,{"mtime_ns","ctime_ns","size"})
            elif op=="chmod":
                self.nodes[path]["mode"]=a["mode"];self.dirty(path,{"ctime_ns","mode"})
            elif op=="unlink":
                require(path in self.nodes and not any(p.startswith(path+b"/")for p in self.nodes),"exact empty directory or file removal")
                require((self.nodes[path]["type"]==0o040000)==bool(a.get("directory")),"same source removal kind")
                del self.nodes[path];self.dirty(self.parent(path),{"mtime_ns","ctime_ns","size","nlink"})
            elif op=="mkdir-root":
                require(path==root and path not in self.nodes,"new source root")
                self.nodes[path]=self.node(0o040000,0o700);self.dirty(b"",{"mtime_ns","ctime_ns","size","nlink"})
            elif op in("rename","rename-root"):
                to=bytes.fromhex(a["to_hex"])if op=="rename"else a["to"].encode()
                dest=root+b"/"+to if op=="rename"else to
                require(to and b"/"not in to and b"\0"not in to and dest not in self.nodes,"exact source rename target")
                moved={p:node for p,node in self.nodes.items()if p==path or p.startswith(path+b"/")}
                require(path in moved,"whole actual renamed subtree")
                for p in moved:del self.nodes[p]
                for p,node in moved.items():self.nodes[dest+p[len(path):]]=node
                self.dirty(dest,{"ctime_ns"});self.dirty(self.parent(dest),{"mtime_ns","ctime_ns","size","nlink"})
            else:raise ValueError("unlisted input filesystem action")
    def check(self,snapshot):
        require(set(snapshot)=={"exists","entries"}and snapshot["exists"]is True and type(snapshot["entries"])is list,
            "complete actual owned root remains present")
        order=[]
        def descend(path):
            order.append(path);node=self.nodes[path]
            if node["type"]==0o040000 and node["mode"]&0o500:
                names=sorted(p for p in self.nodes if p and self.parent(p)==path)
                for name in names:descend(name)
        descend(b"")
        require([bytes.fromhex(r["path_hex"])for r in snapshot["entries"]]==order,"every input-defined node in complete original traversal order")
        for path,row in zip(order,snapshot["entries"]):
            node=self.nodes[path];extra=set()
            if node["type"]==0o100000:extra={"content_hex","content"}
            elif node["type"]==0o040000 and not node["mode"]&0o500:extra={"scan_errno"}
            require(set(row)==BASE|extra and row["path_hex"]==path.hex(),"all complete metadata fields, no unobserved field")
            require(row["type"]==node["type"]and row["mode"]==node["mode"]and
                row["uid"]==self.uid and row["gid"]==self.gid and
                all(integer(row[k])for k in("device","inode","nlink","size","uid","gid","mode","type","mtime_ns","ctime_ns"))
                and row["inode"]>0 and row["nlink"]>0,"full actual metadata and input mode")
            if node["type"]==0o100000:
                require(row["content_hex"]==node["body"].hex()and row["content"]==pin(node["body"])
                    and row["size"]==len(node["body"]),"every complete file byte and length")
            if "scan_errno"in row:require(row["scan_errno"]==13,"real unprivileged original directory scan refusal")
            old=node["observed"]
            if old is not None:
                for key in BASE-{"path_hex"}-node["dirty"]:
                    require(row[key]==old[key],"unchanged physical identity/metadata without a corresponding input effect: "+key)
            node["observed"]=row;node["dirty"].clear()
        return {p:r for p,r in zip(order,snapshot["entries"])}
