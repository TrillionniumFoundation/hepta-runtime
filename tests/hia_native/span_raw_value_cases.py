"""Additive wide Value/typed Map cases; existing bounded domains are unchanged."""
from __future__ import annotations
import json,struct

KEY='$serde_json::private::RawValue'
INVALID=0xffffffff
def encode(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def wrap(raw):return b'{'+encode(KEY)+b':'+encode(raw.decode())+b'}'
def frame(raw,mode='value',operation=1):
 return (b'HJSVS002' if mode=='value' else b'HJSMS002')+struct.pack('<QQ',operation,len(raw))+raw

def leaf_cases():
 roots=[(b'null',b'null'),(b'true',b'true'),(b'false',b'false'),(b'0',b'0'),(b'-0',b'-0.0'),
        (b'1e15',b'1000000000000000.0'),(b'"text"',b'"text"'),(b'[]',b'[]'),(b'{}',b'{}'),
        (b'{"b":2,"a":1,"b":3}',b'{"a":1,"b":3}')]
 for raw,expected in roots:
  for category,payload,result,mode in [
   ('root',wrap(raw),expected,'value'),('array',b'[0,'+wrap(raw)+b',1]',b'[0,'+expected+b',1]','value'),
   ('object',b'{"v":'+wrap(raw)+b',"next":1}',b'{"next":1,"v":'+expected+b'}','value'),
   ('nested',wrap(wrap(raw)),expected,'value'),('map-inner',b'{"v":'+wrap(raw)+b',"next":1}',b'{"next":1,"v":'+expected+b'}','map')]:
   yield category,frame(payload,mode),0,result
 for raw in [b'',b' ',b'01',b'null true',b'1e9999',b'[',b'{"x":}',b'"\\ud800"']:
  yield 'invalid-inner',frame(wrap(raw)),1,b''
  yield 'map-root-literal',frame(wrap(raw),'map'),0,encode({KEY:raw.decode()})
  yield 'map-invalid-inner',frame(b'{"x":'+wrap(raw)+b'}','map'),5,b''
 for raw in [b'{"$serde_json::private::RawValue":1}',b'{"$serde_json::private::RawValue":null}',
             b'{"$serde_json::private::RawValue":"1","a":2}',
             b'{"$serde_json::private::RawValue":"1","$serde_json::private::RawValue":"2"}',
             b'{"a":'+wrap(b'1e9999')+b',"a":0}']:
  yield 'invalid-wrapper',frame(raw),1,b''
 yield 'later-ordinary',frame(b'{"a":0,"$serde_json::private::RawValue":"bad"}'),0,b'{"$serde_json::private::RawValue":"bad","a":0}'
 yield 'parent-key-custody',frame(b'{"first":'+wrap(b'{"a":{}}')+b',"last":{}}'),0,b'{"first":{"a":{}},"last":{}}'
 yield 'independent-depth',frame(b'['*126+wrap(b'['*127+b'0'+b']'*127)+b']'*126),0,b'['*253+b'0'+b']'*253
 yield 'inner-depth-refusal',frame(wrap(b'['*128+b'0'+b']'*128)),1,b''
 yield 'map-root-mixed',frame(b' {"$serde_json::private::RawValue":"invalid","x":'+wrap(b'1')+b'}','map'),0,b'{"$serde_json::private::RawValue":"invalid","x":1}'
 yield 'map-root-nonobject',frame(b'[]','map'),1,b''
 for raw in [b'{"ordinary":1e9999,"x":'+wrap(b'0')+b'}',b'{"ordinary":1e9999,"ordinary":0,"x":'+wrap(b'0')+b'}']:
  yield 'unquoted-number-before-expansion',frame(raw,'map'),1,b''
 raw=wrap(b'0')
 for count in range(1,14):
  yield 'nested-contexts',frame(raw),0,b'0';raw=wrap(raw)
 for position,character in enumerate(KEY):
  encoded_key=(KEY[:position]+'\\u%04x'%ord(character)+KEY[position+1:]).encode()
  yield 'escaped-first-key',frame(b'{"'+encoded_key+b'":"[1]"}'),0,b'[1]'
 for position in range(32):
  for character in ['"','\\','\n','\t','\x00','\x1f','\x7f','é','雪','🙂']:
   value='a'*position+character+'b'*(33-position)
   expected=encode(value)
   yield 'ascii-run-boundary',frame(wrap(expected)),0,expected
 # Every byte at every lane; the locked Rust replay decides complete outcomes.
 for position in range(16):
  for byte in range(256):
   raw=b'"'+b'a'*position+bytes([byte])+b'b'*(16-position)+b'"'
   yield 'ascii-all-byte-lanes',frame(raw),None,None
 for character in ['你好','é','€','😀','\\','"','\n','\x00','\ud800']:
  for position in range(17):
   value='a'*position+character+'b'*(17-position)
   yield 'ascii-unicode-escaped-boundary',frame(json.dumps(value,ensure_ascii=True).encode()),None,None
   if character!='\ud800':
    yield 'ascii-unicode-direct-boundary',frame(json.dumps(value,ensure_ascii=False).encode()),None,None
 for length in (0,1,7,8,9,15,16,17,65535,65536,65537):
  raw=json.dumps({'z':'x'*length,'a':'a\\b\n你好'},ensure_ascii=False,separators=(',',':')).encode()
  yield 'ascii-short-and-large-tail',frame(raw),None,None

def large_cases():
 # Wide input retains its existing extent domain when the string is reparsed.
 inner=b'0'+b' '*((8<<20)+1)
 yield 'raw-above-8MiB',frame(wrap(inner)),0,b'0'

def public_cases():
 return [
  ('nested-path',{'path':{KEY:'"file"'}},'success'),
  ('nested-path-level2',{'path':{KEY:json.dumps({KEY:'"file"'},separators=(',',':'))}},'success'),
  ('root-map-literal',{KEY:'invalid','path':'file'},'success'),
  ('root-map-literal-and-nested',{KEY:'[]','path':{KEY:'"file"'}},'success'),
  ('inner-number-overflow',{'path':{KEY:'1e9999'}},'raw-error'),
  ('unknown-field-inner-error',{'path':'file','ignored':{KEY:'invalid'}},'raw-error'),
  ('extra-wrapper-field',{'path':{KEY:'"file"','extra':0}},'raw-error')]

def public_request(arguments):
 return encode({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'view','arguments':arguments}})

def capacity_cases():
 """Exact growth, unchanged refusal bodies, and persistent-workspace recovery."""
 body=b'['+b'1.5,'*50+b'1.5]';wire=frame(wrap(body))
 def row(group,request,output,workspace,status,result=b'',needed=0,code=32):
  header=b'HJSVR002'+struct.pack('<QQQ',status,len(result),needed) if code==32 else result
  return dict(group=group,wire=request,output_capacity=output,workspace_capacity=workspace,
              code=code,header=header,body=result if code==32 else b'')
 for index,(workspace,status,needed) in enumerate([(16512,2,17044),(17043,2,17044),(17044,2,20097),(20096,2,20097),(20097,0,0)]):
  yield row('growth-'+str(index),wire,1<<20,workspace,status,body if status==0 else b'',needed)
 for index,(capacity,status,needed) in enumerate([(32,3,237),(236,3,237),(237,0,0)]):
  yield row('output-'+str(index),wire,capacity,1<<20,status,body if status==0 else b'',needed)
 for request,status,result,needed in [
  (wire,2,b'',17044),(frame(b'{}'),0,b'{}',0),
  (frame(b'{"$serde_json::private::RawValue":"invalid"}','map'),0,b'{"$serde_json::private::RawValue":"invalid"}',0),
  (frame(wrap(b'1e9999')),1,b'',0),(frame(wrap(b'1')),0,b'1',0),(frame(b'[]'),0,b'[]',0)]:
  yield row('recovery',request,4096,17000,status,result,needed)
 for request,status,result in [
  (frame(b'{"x":'+wrap(b'1e9999')+b'}','map'),5,b''),
  (frame(b'{"ordinary":1e9999,"x":'+wrap(b'0')+b'}','map'),1,b''),
  (frame(b'{"ordinary":1e9999,"ordinary":0,"x":'+wrap(b'0')+b'}','map'),1,b''),
  (frame(b'{"$serde_json::private::RawValue":"invalid","x":'+wrap(b'2')+b'}','map'),0,b'{"$serde_json::private::RawValue":"invalid","x":2}')]:
  yield row('provenance',request,4096,1<<20,status,result)
 for raw,kind,bits in [(b'1',3,1),(b'-1',4,(1<<64)-1),(b'-0',5,1<<63),(b'1e15',5,0x430c6bf526340000)]:
  payload=wrap(raw);request=b'HSJVAL01'+struct.pack('<QQ',2,len(payload))+payload
  yield row('legacy-number',request,4096,1<<20,0,struct.pack('<QQ',kind,bits),code=16)
 for mode in ('value','map'):
  yield row('unknown-'+mode,frame(b'{}',mode,2),4096,1<<20,0,code=INVALID)
 for index,request in enumerate([wire[:0],wire[:23],b'X'+wire[1:],wire[:-1],wire+b' ',wire[:16]+struct.pack('<Q',0)+wire[24:],frame(b'{}','map',0),frame(b'{}','map',(1<<64)-1)]):
  yield row('closed-'+str(index),request,512,65536,0,code=INVALID)
 for capacity in (0,31):yield row('short-output-'+str(capacity),wire,capacity,65536,0,code=0xfffffffe)
 for workspace in (0,8191,16511):yield row('short-work-'+str(workspace),wire,512,workspace,2,needed=16512)
