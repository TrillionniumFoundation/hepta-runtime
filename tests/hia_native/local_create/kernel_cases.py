"""Complete owned-file cases for the current target's exclusive create chain."""
from pathlib import Path
import gzip,hashlib,json,os,stat,struct,subprocess,time

MASK=(1<<64)-1
def sha(raw):return hashlib.sha256(raw).hexdigest()
def frame(path,data):return b'HLCREQ01'+struct.pack('<7Q',1,len(path),len(data),0,0,0,0)+path+data
def cases():
    rows=[]
    def add(name,path,data=b'created\x00bytes\xff\n',setup=(),umask=0o022):
        rows.append(dict(name=name,path=path,data=data,setup=setup,umask=umask))
    add('new-file',b'new')
    add('empty-content',b'empty',b'')
    add('existing-file',b'file',setup=(('file',b'file',b'keep existing bytes'),))
    add('existing-empty',b'file',setup=(('file',b'file',b''),))
    add('existing-directory',b'dir',setup=(('directory',b'dir',b''),))
    add('dangling-symlink',b'link',setup=(('symlink',b'link',b'must-stay-absent'),))
    add('file-symlink',b'link',setup=(('file',b'target',b'keep target'),('symlink',b'link',b'target')))
    add('directory-symlink',b'link',setup=(('directory',b'target',b''),('symlink',b'link',b'target')))
    add('symlink-loop',b'loop',setup=(('symlink',b'loop',b'loop'),))
    add('hard-link',b'alias',setup=(('file',b'original',b'keep both links'),('hardlink',b'alias',b'original')))
    add('empty-path',b'')
    add('missing-parent',b'missing/file')
    add('file-parent',b'parent/file',setup=(('file',b'parent',b'unchanged'),))
    add('trailing-slash',b'absent/')
    add('repeated-slashes',b'dir///created',setup=(('directory',b'dir',b''),))
    add('dot-components',b'./dir/./created',setup=(('directory',b'dir',b''),))
    add('dotdot-components',b'dir/../created',setup=(('directory',b'dir',b''),))
    add('parent-symlink',b'alias/created',setup=(('directory',b'dir',b''),('symlink',b'alias',b'dir')))
    add('umask-027',b'file',umask=0o027)
    add('umask-077',b'file',umask=0o077)
    add('raw-unix-path',b'\xff\xfe\nfile')
    add('nul-first',b'\0bad')
    add('nul-middle',b'good\0bad')
    add('nul-final',b'bad\0')
    add('long-component',b'x'*256)
    add('long-path',b'a/'*2048+b'file')
    for value in range(1,256):
        if value!=47:add('raw-byte-'+str(value),b'raw-'+bytes([value]))
    for size in (2**21-1,2**21,2**21+1,5*2**20+1,8*2**20+1):
        add('content-bytes-'+str(size),b'large',bytes((i*73+11)&255 for i in range(256))*(size//256)+bytes((i*73+11)&255 for i in range(size%256)))
    return rows

def setup(root,spec):
    root.mkdir(mode=0o700)
    base=os.fsencode(root)
    for kind,name,data in spec['setup']:
        path=base+b'/'+name
        if kind=='directory':
            os.mkdir(path);os.chmod(path,0o755)
        elif kind=='file':
            with open(path,'xb') as stream:stream.write(data)
            os.chmod(path,0o640)
        elif kind=='symlink':os.symlink(data,path)
        elif kind=='hardlink':os.link(base+b'/'+data,path)
        else:raise ValueError(kind)

def snapshot(root,destination):
    rows=[]
    base=os.fsencode(root)
    def visit(parent,relative):
        for name in sorted(os.listdir(parent)):
            path=parent+b'/'+name;logical=relative+b'/'+name if relative else name
            info=os.lstat(path)
            row=dict(path_hex=logical.hex(),mode=stat.S_IMODE(info.st_mode),nlink=info.st_nlink)
            if stat.S_ISDIR(info.st_mode):
                row['kind']='directory';rows.append(row);visit(path,logical)
            elif stat.S_ISLNK(info.st_mode):
                row.update(kind='symlink',target_hex=os.readlink(path).hex());rows.append(row)
            elif stat.S_ISREG(info.st_mode):
                with open(path,'rb') as stream:raw=stream.read()
                row.update(kind='file',bytes=len(raw),sha256=sha(raw),content='file-'+str(len(rows))+'.bin.gz')
                with gzip.open(destination/row['content'],'wb',compresslevel=1) as stream:stream.write(raw)
                rows.append(row)
            else:raise AssertionError('Unexpected fixture type')
    visit(base,b'')
    return rows

def run_one(binary,folder,spec,*,native):
    folder.mkdir(exist_ok=False)
    work=folder/'files';setup(work,spec)
    before_dir=folder/'before';before_dir.mkdir()
    before=snapshot(work,before_dir)
    wire=frame(spec['path'],spec['data'])
    stdin=struct.pack('<Q',len(wire))+wire if native else wire
    with gzip.open(folder/'stdin.bin.gz','wb',compresslevel=1) as stream:stream.write(stdin)
    started=time.monotonic()
    result=subprocess.run([str(binary)],input=stdin,cwd=work,env={'PATH':'','LC_ALL':'C'},
                          capture_output=True,timeout=60,umask=spec['umask'])
    elapsed=time.monotonic()-started
    (folder/'stdout.bin').write_bytes(result.stdout)
    (folder/'stderr.bin').write_bytes(result.stderr)
    execution=dict(command=[str(binary)],cwd=str(work),environment={'PATH':'','LC_ALL':'C'},
        timeout_seconds=60,elapsed_seconds=elapsed,exit_code=result.returncode,
        stdin=dict(bytes=len(stdin),sha256=sha(stdin)),
        stdout=dict(bytes=len(result.stdout),sha256=sha(result.stdout)),
        stderr=dict(bytes=len(result.stderr),sha256=sha(result.stderr)))
    (folder/'execution.json').write_text(json.dumps(execution,sort_keys=True,indent=2)+'\n')
    assert result.returncode==0,(spec['name'],result.returncode,result.stdout,result.stderr)
    body=result.stdout
    effects=[]
    if native:
        assert len(body)==56 and struct.unpack_from('<Q',body)[0]==48
        body=body[8:]
        assert len(result.stderr)%96==0
        for index in range(0,len(result.stderr),96):
            raw=result.stderr[index:index+96]
            magic,sequence,action,a,b,c,d,ready,value,error,token,reserved=struct.unpack('<12Q',raw)
            assert magic==int.from_bytes(b'HLCREF01','little') and sequence==index//96+1 and ready==1 and reserved==0
            assert action in (1,2,3)
            assert error<=4095 and (value==(-error&MASK) and token==0 if error else True)
            if action==1:assert (a,b,c,d)==(512,len(spec['path']),0x800c1,0o666)
            if action==2:assert a==1 and 0<c<=2**21 and d==0 and token==0
            if action==3:assert (a,b,c,d,token)==(1,0,0,0,0)
            effects.append(dict(sequence=sequence,action=action,args=[a,b,c,d],raw=value,errno=error,token=token))
    else:
        assert result.stderr==b'HLCREATE-REFERENCE-BEGIN\nHLCREATE-REFERENCE-END\n'
    assert len(body)==48 and body[:8]==b'HLCRER01'
    extent,kind,error,written,reserved=struct.unpack_from('<5Q',body,8)
    assert extent==48 and kind<=3 and reserved==0
    assert (1<=error<=4095) if kind==1 else error==0
    if kind==0:assert written==len(spec['data'])
    if b'\0' in spec['path']:assert kind==2 and not effects
    if native and kind==0:
        expected=[1]+[2]*((len(spec['data'])+2**21-1)//2**21)+[3]
        assert [row['action'] for row in effects]==expected
        assert sum(row['raw'] for row in effects if row['action']==2)==len(spec['data'])
    after_dir=folder/'after';after_dir.mkdir()
    after=snapshot(work,after_dir)
    if spec['name'] in ('existing-file','existing-empty','existing-directory','dangling-symlink','file-symlink','directory-symlink','symlink-loop','hard-link'):
        assert (kind,error)==(1,17),(spec['name'],kind,error)
        assert after==before,(spec['name'],'existing filesystem changed')
    row=dict(name=spec['name'],kind=kind,errno=error,written=written,
             before=before,after=after,effects=effects,execution=execution)
    (folder/'result.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
    return row

def run_corpus(binary,out,*,native):
    out.mkdir(parents=True,exist_ok=False)
    began=time.monotonic();results=[]
    try:
        for index,spec in enumerate(cases()):
            row=run_one(binary,out/str(index),spec,native=native);results.append(row)
            if index%50==0:print(json.dumps(dict(native=native,cases=len(results),elapsed=time.monotonic()-began)),flush=True)
    except BaseException as error:
        (out/'summary.json').write_text(json.dumps(dict(status='FAIL',cases=len(results),error=repr(error)),indent=2)+'\n')
        raise
    summary=dict(status='PASS',cases=len(results),actual_processes=len(results),
        native=native,elapsed_seconds=time.monotonic()-began,
        total_input_bytes=sum(row['execution']['stdin']['bytes'] for row in results),
        total_output_bytes=sum(row['execution']['stdout']['bytes'] for row in results),
        actual_native_kernel_effects=sum(len(row['effects']) for row in results) if native else 0,
        original_rust_execution_performed=not native,public_handler_qualified=False,whole_runtime_replaced=False)
    (out/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    return results,summary

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--original',action='store_true')
    args=parser.parse_args()
    _,summary=run_corpus(args.binary.resolve(strict=True),args.output.resolve(),native=not args.original)
    print(json.dumps(summary,sort_keys=True))
