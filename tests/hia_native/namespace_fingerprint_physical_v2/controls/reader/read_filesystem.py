"""Pure full-tree verification against every frozen owned action; no filesystem replay."""
import stat
from common import encoded,pin,require
TYPE=dict(file=stat.S_IFREG,directory=stat.S_IFDIR,fifo=stat.S_IFIFO,socket=stat.S_IFSOCK,symlink=stat.S_IFLNK)
class Tree:
    def __init__(self,case,uid,gid):
        self.nodes={};self.next=0;self.identities={};self.uid=uid;self.gid=gid
        self.add(b"",case["root_kind"],b"borrowed regular file"if case["root_kind"]=="file"else b"",
                 0o700 if case["root_kind"]=="directory"else None)
        if case["root_kind"]=="file":self.nodes[b""]["mode"]=None
        self.apply(case["setup"])
    def add(self,path,kind,data=b"",mode=None,target=None):
        require(path not in self.nodes,"fresh owned fixture component")
        self.next+=1;self.nodes[path]=dict(token=self.next,kind=kind,data=data,target=target,
            mode=mode if mode is not None else dict(file=0o600,directory=0o700,fifo=0o600,socket=None,symlink=0o777)[kind])
    def apply(self,actions):
        for row in actions:
            path=bytes.fromhex(row["path_hex"]);require(path.hex()==row["path_hex"]and b"/"not in path and b"\0"not in path,
                "complete fixed component action")
            op=row["op"]
            if op in("file","directory","fifo","socket"):
                self.add(path,op,bytes.fromhex(row.get("data_hex","")));continue
            if op=="symlink":self.add(path,op,target=bytes.fromhex(row["target_hex"]));continue
            if op=="hardlink":
                old=self.nodes[bytes.fromhex(row["from_hex"])];require(path not in self.nodes,"fresh real hardlink")
                self.nodes[path]=old;continue
            require(path in self.nodes,"existing owned action component")
            if op=="write":self.nodes[path]["data"]=bytes.fromhex(row["data_hex"])
            elif op=="chmod":self.nodes[path]["mode"]=row["mode"]
            elif op=="rename":
                dest=bytes.fromhex(row["to_hex"]);self.nodes[dest]=self.nodes.pop(path)
            elif op=="unlink":self.nodes.pop(path)
            elif op=="remove_root":
                require(path==b""and set(self.nodes)=={b""},"remove exactly the empty owned root");self.nodes.clear()
            else:raise ValueError("unlisted source-owned action")
    def verify(self,value):
        require(set(value)=={"exists","entries"}and type(value["exists"])is bool and type(value["entries"])is list,
                "whole filesystem snapshot shape")
        require(value["exists"]==bool(self.nodes)and len(value["entries"])==len(self.nodes),"entire existing owned tree")
        require([bytes.fromhex(r["path_hex"])for r in value["entries"]]==sorted(self.nodes),"all raw names in exact captured order")
        actual={}
        for row in value["entries"]:
            path=bytes.fromhex(row["path_hex"]);node=self.nodes[path];kind=node["kind"]
            fixed={"path_hex","mode","type","device","inode","nlink","uid","gid","size","mtime_ns","ctime_ns"}
            if kind=="file":fixed|={"content_hex","content"}
            elif kind=="symlink":fixed.add("target_hex")
            if "scan_errno"in row:fixed.add("scan_errno")
            require(set(row)==fixed and all(type(row[k])is int and row[k]>=0 for k in fixed-{"path_hex","content_hex","content","target_hex"}),
                    "all exact filesystem fields and integer types")
            require(row["type"]==TYPE[kind]and (row["uid"],row["gid"])==(self.uid,self.gid),"actual object kind and owner")
            if node["mode"]is None:node["mode"]=row["mode"]
            require(row["mode"]==node["mode"],"complete file mode after exact actions")
            identity=(row["device"],row["inode"])
            if node["token"]in self.identities:require(self.identities[node["token"]]==identity,"unchanged actual object across rename/content/mode")
            else:self.identities[node["token"]]=identity
            if kind=="file":
                require(row["content_hex"]==node["data"].hex()and row["content"]==pin(node["data"])and
                        row["size"]==len(node["data"]),"every complete file byte")
                require(row["nlink"]==sum(n["token"]==node["token"]for n in self.nodes.values()),"actual full owned hardlink count")
            elif kind=="symlink":require(row["target_hex"]==node["target"].hex()and row["size"]==len(node["target"]),"whole raw symlink target")
            elif kind in("fifo","socket"):require(row["size"]==0,"actual special-file extent")
            if "scan_errno"in row:require(kind=="directory"and row["scan_errno"]==13 and row["mode"]&0o500==0,
                "exact failed directory scan without omitted readable names")
            actual[path]=row
        if actual:
            device=actual[b""]["device"]
            require(all(r["device"]==device for r in actual.values()),"same actual owned filesystem")
        return actual
