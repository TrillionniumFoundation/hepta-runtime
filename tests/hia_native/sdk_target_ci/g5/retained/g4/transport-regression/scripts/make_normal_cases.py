#!/usr/bin/env python3
"""Owned normal protocol files; run only in the ai395 G3 stage."""
from pathlib import Path
import hashlib,json,collections
ROOT=Path(__file__).resolve().parents[1]
MAX=16*1024*1024
compact=lambda value:json.dumps(value,ensure_ascii=False,separators=(',',':'))
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def ping(identifier,padding=0,ending=b'\n'):
    obj={'jsonrpc':'2.0','id':identifier,'method':'ping'}
    if padding:obj['params']={'padding':'a'*padding}
    return compact(obj).encode()+ending

def sized_ping(identifier,total,ending=b'\n'):
    base=compact({'jsonrpc':'2.0','id':identifier,'method':'ping','params':{'padding':''}}).encode()
    extra=total-len(base)-len(ending)
    assert extra>=0
    raw=ping(identifier,extra,ending)
    assert len(raw)==total
    return raw

def main():
    directory=ROOT/'cases/inputs';directory.mkdir()
    rows=[];files={}
    def add(label,data,mode='async',chunk=8192,**options):
        name='cases/inputs/'+label+'.bin'
        (ROOT/name).write_bytes(data)
        files[name]={'bytes':len(data),'sha256':sha(data)}
        rows.append({'label':label,'mode':mode,'input_file':name,'chunk_size':chunk,**options})
    add('empty-eof',b'')
    add('one-lf',ping(1))
    add('three-lf',b''.join(ping(i) for i in range(1,4)))
    add('three-crlf',b''.join(ping(i,ending=b'\r\n') for i in range(1,4)))
    add('empty-lines-between',b'\n\r\n'+ping(1)+b'\n'+ping(2)+b'\r\n')
    add('bom-complete-line',b'\xef\xbb\xbf'+ping('ordinary'))
    add('unicode-id',ping('普通'))
    for suffix in [b'',b'\r']:
        ending='plain' if not suffix else 'cr'
        tail=ping(2,ending=suffix)
        add('tail-only-'+ending,tail)
        add('full-then-tail-'+ending,ping(1)+tail)
        add('codec-tail-only-'+ending,tail,'codec-eof')
        add('codec-full-then-tail-'+ending,ping(1)+tail,'codec-eof')
    for chunk in [1,2,3,7,64,8192]:
        add('fragment-'+str(chunk),ping(1)+ping(2,ending=b'\r\n'),chunk=chunk)
    raw=ping('fragmented')
    for position in [1,7,len(raw)-1]:
        add('cancel-pending-'+str(position),raw,chunk=3,cancel_receive_after=position)
    for total in [MAX-1,MAX,MAX+1]:
        add('default-line-'+str(total),sized_ping(1,total)+ping(2),chunk=8192)
    add('default-crlf-exact',sized_ping(1,MAX,b'\r\n')+ping(2),chunk=16384)
    add('default-crlf-one-over',sized_ping(1,MAX+1,b'\r\n')+ping(2),chunk=16384)
    # A valid, normally sized request under a deliberately small configured cap
    # verifies the same bounded discard state without another large fixture.
    add('configured-cap-discard-resume',sized_ping(1,129)+ping(2),chunk=17,max_line_length=128)
    rows.append({'label':'eof-response-drain-child-cancel','mode':'shutdown'})
    transport_rows=list(rows)
    models=[json.loads(line) for line in (ROOT/'cases/message-normal.jsonl').read_bytes().splitlines()]
    for row in models:rows.append(dict(row,mode='model'))
    raw=b''.join((compact(row)+'\n').encode() for row in rows)
    (ROOT/'cases/normal.jsonl').write_bytes(raw)
    manifest={'schema':'hepta.g3.normal-cases.v1','cases':len(rows),'transport_cases':len(transport_rows),
        'model_cases':len(models),'modes':dict(collections.Counter(r['mode'] for r in rows)),
        'sha256':sha(raw),'files':files,'default_max_line_length':MAX,
        'only_normal_protocol_data':True,'external_targets':False,'malformed_protocol_domain':False}
    (ROOT/'cases/manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:manifest[k] for k in ['cases','transport_cases','model_cases','modes','sha256']},sort_keys=True))

if __name__=='__main__':main()
