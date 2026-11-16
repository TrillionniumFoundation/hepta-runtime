"""Exact helper functions retained from the ordinary ordered eight-tool qualifier."""
from pathlib import Path
import base64,hashlib,json,os,shutil,stat
sha=lambda b:hashlib.sha256(b).hexdigest()
wire=lambda x:json.dumps(x,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
def snapshot(root):
    rows={}
    for folder,dirs,names in os.walk(root):
        for name in sorted(dirs+names):
            p=Path(folder)/name;st=p.lstat();rel=str(p.relative_to(root))
            row={'mode':stat.S_IMODE(st.st_mode),'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'gid':st.st_gid}
            if stat.S_ISDIR(st.st_mode):row['kind']='directory'
            elif stat.S_ISREG(st.st_mode):
                raw=p.read_bytes();row.update(kind='file',bytes=len(raw),sha256=sha(raw),data_base64=base64.b64encode(raw).decode())
            else:raise AssertionError(('unexpected fixture file type',rel))
            rows[rel]=row
    return rows

def comparable(rows):
    return {name:{k:v for k,v in row.items() if k not in {'device','inode','uid','gid'}} for name,row in rows.items()}

def setup(root):
    assert not root.exists();root.mkdir()
    (root/'OWNED-FIXTURE.json').write_bytes(wire({'owner':'g5-public-closure-6780-v1','purpose':'ordinary owned eight-tool comparison'}))
    work=root/'workspace';(work/'sub/tree').mkdir(parents=True);(root/'controller-state').mkdir(mode=0o700)
    (work/'seed.txt').write_bytes('alpha\nbeta 中\n'.encode())
    (work/'sub/nested.txt').write_bytes(b'ordinary nested file\n')
    (work/'sub/moveme.txt').write_bytes(b'ordinary file move\n')
    (work/'sub/tree/leaf.txt').write_bytes(b'ordinary directory move\n')
    config={'state_dir':str(root/'controller-state'),'controller_workspace_roots':[str(work)],'hosts':{'owned':{'ssh_target':'not-contacted-owned-fixture','remote_state_dir':'/unused-state'}}}
    (root/'runtime-config.json').write_bytes(wire(config));return work,root/'runtime-config.json'

def retire(root,out):
    assert root.parent==out and root.name=='fixture' and root.is_dir() and not root.is_symlink()
    assert json.loads((root/'OWNED-FIXTURE.json').read_bytes())['owner']=='g5-public-closure-6780-v1'
    for folder,dirs,names in os.walk(root):
        for name in dirs+names:
            p=Path(folder)/name;assert not p.is_symlink() and p.lstat().st_uid==os.geteuid()
    shutil.rmtree(root)

def body_bytes(raw):
    marker=b',"result":';start=raw.index(marker)+len(marker);assert raw.endswith(b'}')
    body=raw[start:-1];assert json.loads(body)==json.loads(raw)['result'];return body
