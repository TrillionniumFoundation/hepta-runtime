"""Actual fixed ELF and Linux effects. This is not the original-Rust gate."""
from pathlib import Path
import argparse,hashlib,json,os,selectors,signal,struct,subprocess,time,traceback
def sha(raw):return hashlib.sha256(raw).hexdigest()
def frame(mode,path,text,expected):
    return b'HTXTQ001'+struct.pack('<7Q',1,mode,len(path),len(text),len(expected),0,0)+path+expected+text
def drop(generation):return b'HTXTQ001'+struct.pack('<7Q',2,0,0,0,0,generation,0)
def envelope(raw):return struct.pack('<Q',len(raw))+raw
def parse(raw):
    rows=[];offset=0
    while offset<len(raw):
        size=struct.unpack_from('<Q',raw,offset)[0];offset+=8
        assert size>=64 and size<=len(raw)-offset
        magic,code,gen,seq,n,live,phase,reserved=struct.unpack_from('<8s7Q',raw,offset)
        assert magic==b'HTXTER01' and n==size-64 and live==0 and reserved==0
        rows.append({'code':code,'generation':gen,'sequence':seq,'phase':phase,'body':raw[offset+64:offset+size]})
        offset+=size
    return rows
def effects(raw):
    assert len(raw)%256==0
    rows=[]
    for at in range(0,len(raw),256):
        block=raw[at:at+256];header=struct.unpack_from('<8s7Q',block)
        magic,gen,seq,kind,phase,actual,cap,z=header
        assert magic==b'HTXTEF01' and z==0
        fx=struct.unpack_from('<8s15Q',block,64)
        assert fx[:4]==(b'HTXTFX01',seq,gen,kind) and fx[12:]==(0,1,0,0)
        rows.append({'generation':gen,'sequence':seq,'kind':kind,'phase':phase,'raw':actual,
                     'effect':list(fx[4:]),'fd_slots':list(struct.unpack_from('<8q',block,192))})
    return rows
def run(elf,folder,wire,flag=None):
    folder.mkdir();command=[str(elf)]+([flag] if flag else []);started=time.monotonic_ns()
    p=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=folder)
    timed=False
    try:out,err=p.communicate(wire,timeout=60)
    except subprocess.TimeoutExpired:timed=True;p.kill();out,err=p.communicate()
    finished=time.monotonic_ns()
    for name,raw in [('stdin.bin',wire),('stdout.bin',out),('stderr.bin',err)]: (folder/name).write_bytes(raw)
    record={'command':command,'cwd':str(folder),'pid':p.pid,'started_monotonic_ns':started,
      'finished_monotonic_ns':finished,'elapsed_seconds':(finished-started)/1e9,'timeout_seconds':60,
      'exit_code':p.returncode,'timed_out':timed,'start_error':None,
      'streams':{name:{'bytes':len(raw),'sha256':sha(raw)} for name,raw in [('stdin',wire),('stdout',out),('stderr',err)]}}
    (folder/'process.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    assert not timed
    return record,parse(out),effects(err) if flag else err
def sync(elf,folder,wire,hook):
    folder.mkdir();command=[str(elf),'--sync'];started=time.monotonic_ns()
    p=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=folder)
    sent=bytearray(envelope(wire));p.stdin.write(sent);p.stdin.flush()
    out=bytearray();err=bytearray();pending=bytearray();selector=selectors.DefaultSelector()
    selector.register(p.stdout,selectors.EVENT_READ,'out');selector.register(p.stderr,selectors.EVENT_READ,'err')
    timed=False
    try:
        while True:
            assert time.monotonic_ns()-started<60_000_000_000
            ready=selector.select(1)
            for key,_ in ready:
                raw=os.read(key.fileobj.fileno(),65536);assert raw,'unexpected EOF'
                if key.data=='out':out.extend(raw)
                else:
                    err.extend(raw);pending.extend(raw)
                    while len(pending)>=256:
                        block=bytes(pending[:256]);del pending[:256];row=effects(block)[0];hook(row)
                        ack=b'HTXTACK1'+struct.pack('<2Q',row['generation'],row['sequence'])
                        p.stdin.write(ack);p.stdin.flush();sent.extend(ack)
            if len(out)>=8 and len(out)==8+struct.unpack_from('<Q',out)[0]:break
        p.stdin.close();p.wait(timeout=10)
        out.extend(p.stdout.read());err.extend(p.stderr.read())
    except BaseException:
        p.kill();p.wait();out.extend(p.stdout.read());err.extend(p.stderr.read());raise
    finally:
        finished=time.monotonic_ns();selector.close()
        for name,raw in [('stdin.bin',sent),('stdout.bin',out),('stderr.bin',err)]: (folder/name).write_bytes(raw)
        record={'command':command,'cwd':str(folder),'pid':p.pid,'started_monotonic_ns':started,
          'finished_monotonic_ns':finished,'elapsed_seconds':(finished-started)/1e9,'timeout_seconds':60,
          'exit_code':p.returncode,'streams':{name:{'bytes':len(raw),'sha256':sha(raw)} for name,raw in [('stdin',sent),('stdout',out),('stderr',err)]}}
        (folder/'process.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    assert p.returncode==0
    return parse(out),effects(err)
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(args.manifest.read_bytes());elf=args.manifest.parent/manifest['elf'];assert sha(elf.read_bytes())==manifest['elf_sha256']
    files=out/'files';files.mkdir();path=files/'file';name=os.fsencode(path)
    first=b'hello\n';second='\u4e2d\U0001f642'.encode();third=b'\0tail\n'
    requests=[frame(1,name,first,b'absent'),drop(1),frame(2,name,second,sha(first).encode()),drop(2),
              frame(3,name,third,sha(second).encode()),drop(3)]
    record,rows,fx=run(elf,out/'chain',b''.join(map(envelope,requests)),'--trace')
    assert record['exit_code']==0 and len(rows)==6
    for row,expected in zip(rows[::2],(first,second,second+third)):
        body=row['body'];assert row['code']==160 and body[:8]==b'HTXTR001' and struct.unpack_from('<Q',body,8)[0]==0
        assert body[120:152]==hashlib.sha256(expected).digest()
    assert all(row['code']==64 and struct.unpack_from('<Q',row['body'],8)[0]==2 for row in rows[1::2])
    assert path.read_bytes()==second+third and path.stat().st_mode&0o777==0o600
    huge=files/'large';old=b'x'*(4*1024*1024);huge.write_bytes(old);huge.chmod(0o600)
    addition=b'Y'*65536
    record,rows,largefx=run(elf,out/'sha-windows',envelope(frame(3,os.fsencode(huge),addition,sha(old).encode())),'--trace')
    assert record['exit_code']==0 and rows[0]['code']==160 and rows[0]['body'][120:152]==hashlib.sha256(old+addition).digest()
    assert huge.read_bytes()==old+addition
    malformed=frame(1,name,b'x',b'absent')[:-1]
    record,rows,quiet=run(elf,out/'invalid',envelope(malformed))
    assert record['exit_code']==0 and rows[0]['code']==0xffffffff and quiet==b''
    error_path=os.fsencode(files)+b'/'+b'a'*256
    record,rows,errorfx=run(elf,out/'errno-child',envelope(frame(1,error_path,b'x',b'absent')),'--trace')
    assert record['exit_code']==0 and rows[0]['code']<0xffff0000 and struct.unpack_from('<Q',rows[0]['body'],8)[0]==1
    assert any(row['kind']==19 for row in errorfx)
    race=files/'race';fired=[]
    def hook(row):
        if row['kind']==5 and not fired:race.write_bytes(b'competitor\n');fired.append(row['sequence'])
    rows,racefx=sync(elf,out/'race',frame(1,os.fsencode(race),b'ours\n',b'absent'),hook)
    assert fired and struct.unpack_from('<Q',rows[0]['body'],8)[0]==1 and race.read_bytes()==b'competitor\n'
    assert sorted(path.name for path in files.iterdir())==['file','large','race']
    record,rows,quiet=run(elf,out/'partial-header',b'abc')
    assert record['exit_code']==74 and rows==[] and quiet==b''
    record,rows,quiet=run(elf,out/'partial-frame',struct.pack('<Q',64)+b'abc')
    assert record['exit_code']==74 and rows==[] and quiet==b''
    record,rows,quiet=run(elf,out/'empty',b'')
    assert record['exit_code']==0 and rows==[] and quiet==b''
    result={'status':'PASS','actual_elf_processes':8,'actual_hia_requests':10,'effects':len(fx)+len(largefx)+len(errorfx)+len(racefx),
      'full_result_bytes':True,'original_reference_executed':False,'production_mcp_route_replaced':False,'manifest_sha256':sha(args.manifest.read_bytes())}
    (out/'RESULT.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result),flush=True)
if __name__=='__main__':main()
