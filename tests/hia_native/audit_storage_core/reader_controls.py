"""Physical rehashed evidence controls; admission/verification never executes HIA or Rust."""
from pathlib import Path
import gzip
import io
import json
import shutil
import struct
from common import ROOT,encoded,files,loads,pin,read,require,source
import read_capture
import read_only_guard

NAMES=('input-byte','output-tail','workspace-refusal','missing-call','effect-ack',
       'missing-operation','original-stdout','original-filesystem','compiler-output-tail',
       'compiled-image','registry-source','source-copy','original-stderr','original-pid')

def copy_capture(source_root,destination):
    require(not destination.exists(),'fresh physical control copy')
    admitted=files(source_root)
    destination.mkdir(parents=True)
    for name in sorted(admitted):
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
        raw=read(source_root/name);require(pin(raw)=={k:admitted[name][k] for k in ('bytes','sha256')},'exact copied source evidence')
        target.write_bytes(raw)
        target.chmod((source_root/name).stat().st_mode&0o777)
    require(files(destination)==admitted,'full independently copied evidence bytes')
    return admitted

def put(path,value):path.write_bytes(encoded(value))

def rehash(root):
    m=loads(read(root/'CAPTURE.json'));m['files']=files(root,('CAPTURE.json',));put(root/'CAPTURE.json',m)

def native_report(root):
    p=root/'native/NATIVE.json';m=loads(read(p))
    for key,name in (('buffers','buffers.bin.gz'),('invocations','INVOCATIONS.json'),('effects','effects.jsonl'),
                     ('observations','OBSERVATIONS.json'),('retirement','RETIREMENT.json')):
        m[key]=pin(read(root/'native'/name))
    put(p,m)

def original_report(root):
    p=root/'original/process.json';m=loads(read(p))
    for kind in ('stdin','stdout','stderr'):m[kind]=pin(read(root/'original'/('original.'+kind)))
    put(p,m)
    p=root/'original/ORIGINAL.json';r=loads(read(p))
    for key,name in (('process','process.json'),('observations','OBSERVATIONS.json'),('retirement','RETIREMENT.json')):
        r[key]=pin(read(root/'original'/name))
    put(p,r)

def mutate_buffer(root,kind):
    path=root/'native/buffers.bin.gz';raw=bytearray(gzip.decompress(read(path)))
    inv=loads(read(root/'native/INVOCATIONS.json'))
    at=8;chosen=None
    for index,row in enumerate(inv):
        require(raw[at:at+8]==b'AIOCAL01','control parses real complete call')
        fields=struct.unpack_from('<9Q',raw,at+8)
        ni,no,nw=fields[5:8];sizes=[ni+16,no+16,nw+16]
        start=at+80;positions=[start]
        for size in sizes*2:positions.append(positions[-1]+size)
        if ((kind=='input-byte') or (kind=='output-tail' and row['probe'] is None and row['module']==0)
                or (kind=='workspace-refusal' and row['probe'] is not None and nw>0)
                or kind=='missing-call'):
            chosen=(index,at,positions,sizes);break
        at=positions[-1]
    require(chosen is not None,'existing complete native record selected')
    index,at,positions,sizes=chosen
    if kind=='missing-call':
        del raw[at:positions[-1]];inv.pop(index)
        # Deliberately retain all subsequent real call identities. Their missing
        # predecessor is a semantic omission, not an opaque gzip corruption.
    else:
        buffer_index=0 if kind=='input-byte' else (4 if kind=='output-tail' else 5)
        offset=0 if kind in ('input-byte','workspace-refusal') else fields[6]-1
        raw[positions[buffer_index]+offset]^=1
        if kind=='input-byte':
            raw[positions[3]]^=1
        before=[bytes(raw[positions[j]:positions[j+1]]) for j in range(3)]
        after=[bytes(raw[positions[j]:positions[j+1]]) for j in range(3,6)]
        inv[index]['before']=[pin(x) for x in before];inv[index]['after']=[pin(x) for x in after]
    path.write_bytes(gzip.compress(bytes(raw),compresslevel=1,mtime=0))
    put(root/'native/INVOCATIONS.json',inv);native_report(root)

def mutate(root,name):
    if name in NAMES[:4]:mutate_buffer(root,name)
    elif name=='effect-ack':
        p=root/'native/effects.jsonl';rows=[loads(x) for x in read(p).splitlines()]
        r=rows[0];raw=bytearray.fromhex(r['acknowledgement_hex']);raw[8]^=1;r['acknowledgement_hex']=raw.hex()
        p.write_bytes(b''.join(json.dumps(x,sort_keys=True,separators=(',',':')).encode()+b'\n' for x in rows))
        native_report(root)
    elif name=='missing-operation':
        p=root/'native/OBSERVATIONS.json';rows=loads(read(p));rows.pop();put(p,rows);native_report(root)
    elif name=='original-stdout':
        p=root/'original/original.stdout';raw=bytearray(read(p));raw[8]^=1;p.write_bytes(raw);original_report(root)
    elif name=='original-filesystem':
        p=root/'original/OBSERVATIONS.json';rows=loads(read(p));rows[0]['after'][0]['stat']['st_mode']^=1
        put(p,rows);original_report(root)
    elif name=='compiler-output-tail':
        folder=root/'build/modules/audit-record-io'
        p=folder/'module.output.bin';raw=bytearray(read(p));raw[-1]^=1;p.write_bytes(raw)
        receipt=loads(read(folder/'module.receipt.json'));receipt['output_sha256']=pin(raw)['sha256']
        put(folder/'module.receipt.json',receipt)
        stdout=loads(read(folder/'module.stdout.log'));stdout['output_sha256']=pin(raw)['sha256'];put(folder/'module.stdout.log',stdout)
        build=loads(read(folder/'build.json'));build['compile_receipt']=receipt;put(folder/'build.json',build)
    elif name=='compiled-image':
        p=root/'build/modules/audit-record-io/module.image.bin';raw=bytearray(read(p));raw[-1]^=1;p.write_bytes(raw)
        p=root/'build/modules/audit-record-io/manifest.json';m=loads(read(p));m['image_sha256']=pin(raw)['sha256'];put(p,m)
        p=root/'build/BUILD.json';b=loads(read(p));b['modules']['audit-record-io']['image']=pin(raw)
        b['modules']['audit-record-io']['manifest'].update(pin(read(root/'build/modules/audit-record-io/manifest.json')));put(p,b)
    elif name=='registry-source':
        folder=sorted((root/'vendor').iterdir())[0]
        checksum=loads(read(folder/'.cargo-checksum.json'))
        rel=next(n for n in sorted(checksum['files']) if n.endswith('.rs'))
        p=folder/rel;raw=read(p)+b'\n';p.write_bytes(raw)
        checksum['files'][rel]=pin(raw)['sha256'];put(folder/'.cargo-checksum.json',checksum)
    elif name=='source-copy':
        p=root/'source/protocol.py';p.write_bytes(read(p)+b'\n')
    elif name=='original-stderr':
        p=root/'original/original.stderr';raw=read(p);require(b'OBSERVED_ORIGINAL_ERROR ' in raw,'actual original errors')
        p.write_bytes(raw.replace(b'OBSERVED_ORIGINAL_ERROR ',b'OBSERVED_ORIGINAL_ERR0R ',1));original_report(root)
    elif name=='original-pid':
        p=root/'original/process.json';m=loads(read(p));m['pid']+=1;put(p,m);original_report(root)
    else:raise ValueError('unknown physical control')
    rehash(root)

def rejected(root):
    try:read_capture.semantic(root)
    except ValueError as error:return dict(refused=True,error=str(error))
    raise ValueError('physical mutation was accepted')

def run(capture,output):
    output.mkdir(parents=True,exist_ok=False)
    baseline=read_capture.semantic(capture)
    rows=[]
    for label in ('one','nested/two'):
        target=output/label
        copy_capture(capture,target)
        proof=read_only_guard.guarded(lambda:read_capture.semantic(target),roots=[target,ROOT],
                                     foreign_path=str(capture/'CAPTURE.json'))
        require(proof['evidence']==baseline,'complete independent physical admission')
        report=label.replace('/','-')+'.guard.json';put(output/report,proof)
        rows.append(dict(name=label,kind='admission',capture=label,proof=report,
                         physical=files(target),evidence=baseline))
    for name in NAMES:
        target=output/'refusals'/name
        copy_capture(capture,target);mutate(target,name)
        proof=read_only_guard.guarded(lambda:rejected(target),roots=[target,ROOT],
                                     foreign_path=str(capture/'CAPTURE.json'))
        report=name+'.guard.json';put(output/report,proof)
        rows.append(dict(name=name,kind='refusal',capture='refusals/'+name,proof=report,
                         physical=files(target),evidence=proof['evidence']))
    report=dict(schema='hepta.audit-record-io.reader-controls.v1',status='PASS',source_manifest_sha256=source(),
        names=list(NAMES),admissions=2,refusals=len(NAMES),rows=rows,native_or_rust_executions=0,reader_writes=0)
    put(output/'CONTROLS.json',report)
    return report

def verify(output,baseline):
    report=loads(read(output/'CONTROLS.json'))
    require(report['status']=='PASS' and report['source_manifest_sha256']==source()
        and report['names']==list(NAMES) and report['admissions']==2 and report['refusals']==14
        and len(report['rows'])==16,'all original physical reader controls')
    expected=['one','nested/two',*NAMES]
    for name,row in zip(expected,report['rows'],strict=True):
        require(row['name']==name,'fixed complete control order')
        folder=output/row['capture']
        require(files(folder)==row['physical'],'complete physical mutation or admitted copy unchanged')
        observed=read_capture.semantic(folder) if row['kind']=='admission' else rejected(folder)
        require(observed==row['evidence'],'same retained complete reader verdict')
        if row['kind']=='admission':require(observed==baseline,'same complete corpus on relocated path')
        proof=loads(read(output/row['proof']))
        require(proof['evidence']==observed and proof['before']==proof['after']
            and proof['native_or_rust_executions']==proof['reader_writes']==0
            and len(proof['probes'])==12 and len({p['name'] for p in proof['probes']})==12,
            'complete fixed-reader unchanged-byte guard and all twelve refusals')
    return dict(admissions=2,refusals=14,guard_probes=192,all_physical_controls_retained=True,
                native_or_rust_executions=0,reader_writes=0)
