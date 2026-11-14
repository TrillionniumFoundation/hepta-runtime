#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual seven-image ELF against unchanged original strict-UTF8 batch helpers."""
from __future__ import annotations
import hashlib,json,os,random,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_local_service as shared
ROOT=shared.ROOT
COUNTS={'elf_requests':0,'original_batch_comparisons':0,'expected_domain_refusals':0,'expected_parameter_refusals':0,'original_budget_boundary_pairs':0,'original_failure_comparisons':0}
ORIGINAL_MULTI_SHA='6f83b3e1031642e9981310916181858941dec51bb1696a79087beeb60a6e3eb5'
REDACTED='multi-file read could not complete; verify configured read roots, regular single-link files, strict UTF-8 and byte budgets'
class MultiServiceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  shared.NativeServiceTests.setUpClass()
  cls.executable=shared.NativeServiceTests.executable;cls.manifest=shared.NativeServiceTests.manifest;cls.metadata=shared.NativeServiceTests.metadata
  assert len(cls.metadata['profile'])==7
  assert cls.metadata['profile'][0]['call_mask']==126 and cls.metadata['profile'][5]['call_mask']==30
  assert cls.metadata['profile'][3]['workspace_capacity']==8<<20
  assert cls.metadata['profile'][3]['flags']==3 and cls.metadata['profile'][3]['call_mask']==4
  raw=(ROOT/'src/mcp/runtime/multi_read_host.py').read_bytes();assert hashlib.sha256(raw).hexdigest()==ORIGINAL_MULTI_SHA
  namespace=dict(vars(shared.NativeServiceTests.original));namespace.update(__name__='hia_original_multi_service',__file__=str(ROOT/'src/mcp/runtime/multi_read_host.py'))
  exec(compile(raw,str(ROOT/'src/mcp/runtime/multi_read_host.py'),'exec'),namespace)
  cls.original=staticmethod(namespace['multi_read']);cls.wire_size=staticmethod(namespace['_wire_size'])
 @classmethod
 def tearDownClass(cls):
  assert hashlib.sha256((ROOT/'src/mcp/runtime/multi_read_host.py').read_bytes()).hexdigest()==ORIGINAL_MULTI_SHA
  assert hashlib.sha256((ROOT/'src/mcp/runtime/binary_file.py').read_bytes()).hexdigest()==shared.ORIGINAL_SHA
 def call(self,service,args,identity='batch 雪"\n',raw=False):
  result=service.tool('read_multiple_files',args,identity=identity,raw=raw);COUNTS['elf_requests']+=1;return result
 def compare(self,service,root,args):
  file_limit=16384 if args.get('max_file_bytes') is None else args['max_file_bytes']
  response_limit=65536 if args.get('max_response_bytes') is None else args['max_response_bytes']
  q={'files':[{'path':p,'root':str(root)} for p in args['paths']],'max_file_bytes':file_limit,'max_response_bytes':response_limit}
  expected=self.original(q)
  error,text=self.call(service,args);self.assertFalse(error,text);self.assertEqual(json.loads(text),expected)
  self.assertEqual(text,json.dumps(expected,ensure_ascii=False,sort_keys=True,separators=(',',':')))
  self.assertEqual(self.wire_size(expected),len(json.dumps({'content':[{'type':'text','text':text}],'isError':False},ensure_ascii=False,separators=(',',':')).encode()))
  COUNTS['original_batch_comparisons']+=1;return expected
 def failure(self,service,args,text=REDACTED):
  if text==REDACTED:
   root=service.proc.args[-1]
   q={'files':[{'path':path,'root':root} for path in args['paths']],
      'max_file_bytes':16384 if args.get('max_file_bytes') is None else args['max_file_bytes'],
      'max_response_bytes':65536 if args.get('max_response_bytes') is None else args['max_response_bytes']}
   with self.assertRaises((ValueError,OSError)):self.original(q)
   COUNTS['original_failure_comparisons']+=1
  failed,message=self.call(service,args);self.assertTrue(failed,message);self.assertEqual(message,text);COUNTS['expected_domain_refusals']+=1
 def test_exact_original_successes(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);contents=['','alpha\nbeta\r\n',''.join(chr(i) for i in range(32))+'"\\雪😀\u2028\u2029\ufeff','snow 雪\n'*100,'a'*16384,'b'*65536,'😀'*16384];paths=[]
   for index,text in enumerate(contents):
    path=root/(f'file-{index}'+('"\\\n\t雪😀' if index==2 else ''));path.write_bytes(text.encode());paths.append(str(path))
   with shared.Session(self.executable,root) as service:
    service.ready()
    for index,path in enumerate(paths):
     options={'max_file_bytes':65536,'max_response_bytes':262144} if index>=5 else {}
     self.compare(service,root,{'host':'native-local','paths':[path],**options})
    for selected in [paths[:1],paths[:3],paths[3:5],list(reversed(paths[:5]))]:self.compare(service,root,{'host':'native-local','paths':selected})
    self.compare(service,root,{'host':'native-local','paths':paths[:3],'max_file_bytes':None,'max_response_bytes':None})
    sixteen=[]
    for i in range(16):
     path=root/f'small-{i}';path.write_bytes(('row\0\n雪'+str(i)).encode());sixteen.append(str(path))
    self.compare(service,root,{'host':'native-local','paths':sixteen})
    self.compare(service,root,{'host':'native-local','paths':list(reversed(sixteen)),'max_file_bytes':128,'max_response_bytes':262144})
    rng=random.Random(0xB17C4)
    for _ in range(24):self.compare(service,root,{'host':'native-local','paths':rng.sample(sixteen,rng.randint(1,16)),'max_file_bytes':128,'max_response_bytes':262144})
    # Same persistent IO owner alternates root and nested handler callers.
    failed,text=service.tool('binary_read',{'host':'native-local','path':paths[1]});self.assertFalse(failed)
    self.compare(service,root,{'host':'native-local','paths':paths[:3]})
    failed,text=service.tool('host_list',{});self.assertFalse(failed);self.assertEqual(json.loads(text)['hosts'][0]['name'],'native-local')
 def test_exact_shared_escaped_budget(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);path=root/'escaped"\\雪';path.write_bytes(('\0\t\n\r"\\雪😀'*100).encode())
   with shared.Session(self.executable,root) as service:
    service.ready()
    for count in [1,2,3,8]:
     paths=[str(path)]
     for i in range(1,count):
      extra=root/f'other-{i}';extra.write_bytes(('control\0\b\t\n雪'*33).encode());paths.append(str(extra))
     q={'files':[{'path':p,'root':str(root)} for p in paths],'max_file_bytes':16384,'max_response_bytes':262144}
     expected=self.original(q);limit=self.wire_size(expected);self.assertTrue(1024<limit<262144)
     for adjustment in [0,1]:self.compare(service,root,{'host':'native-local','paths':paths,'max_response_bytes':limit+adjustment})
     with self.assertRaises(ValueError):self.original(dict(q,max_response_bytes=limit-1))
     self.failure(service,{'host':'native-local','paths':paths,'max_response_bytes':limit-1});COUNTS['original_budget_boundary_pairs']+=1
 def test_failures_are_atomic_and_redacted(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);good=root/'good';good.write_text('hardlink-source',encoding='utf-8')
   bad=root/'invalid-utf8';bad.write_bytes(b'bad\xff');large=root/'large';large.write_bytes(b'x'*65537)
   hard=root/'hard';os.link(good,hard);symlink=root/'symbolic';symlink.symlink_to(good)
   folder=root/'directory';folder.mkdir();missing=root/'missing'
   with shared.Session(self.executable,root) as service:
    service.ready();prefix=root/'prefix';prefix.write_text('PRIVATE-FIRST-FILE-CONTENT-MUST-NOT-LEAK',encoding='utf-8')
    for failure in [bad,large,hard,symlink,folder,missing,root/'.hepta-sidecar']:
     self.failure(service,{'host':'native-local','paths':[str(prefix),str(failure)],'max_file_bytes':65536,'max_response_bytes':262144})
     self.compare(service,root,{'host':'native-local','paths':[str(prefix)]})
    almost=root/'16385';almost.write_bytes(b'x'*16385);self.failure(service,{'host':'native-local','paths':[str(almost)]})
    small=root/'small';small.write_bytes(b'ab');self.failure(service,{'host':'native-local','paths':[str(small)],'max_file_bytes':1})
    self.compare(service,root,{'host':'native-local','paths':[str(small)],'max_file_bytes':2,'max_response_bytes':1024})
    outside=str(root.parent/'outside-batch-boundary')
    self.failure(service,{'host':'native-local','paths':[str(missing),outside]},f'path `{outside}` is outside configured read roots on host `native-local`')
 def test_original_validation_order(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);path=root/'value';path.write_text('value',encoding='utf-8');base={'host':'native-local','paths':[str(path)]}
   with shared.Session(self.executable,root) as service:
    service.ready()
    invalid=[{},dict(base,paths=None),dict(base,paths='x'),dict(base,paths=[None]),dict(base,host=None),dict(base,extra=1),dict(base,max_file_bytes=-1),dict(base,max_file_bytes=1.0),dict(base,max_file_bytes=True),dict(base,max_file_bytes=1<<64),dict(base,max_response_bytes='1024')]
    for args in invalid:
     result=self.call(service,args,raw=True);self.assertEqual(result['error']['code'],-32602);COUNTS['expected_parameter_refusals']+=1
    count_error='read_multiple_files requires 1..16 paths'
    self.failure(service,dict(base,paths=[],max_file_bytes=0,host='unknown'),count_error)
    self.failure(service,dict(base,paths=[str(path)]*17),count_error)
    for value in [0,65537,(1<<64)-1]:self.failure(service,dict(base,max_file_bytes=value),'max_file_bytes must be 1..65536; larger files require binary_read')
    for value in [0,1023,262145,(1<<64)-1]:self.failure(service,dict(base,max_response_bytes=value),'max_response_bytes must be 1024..262144')
    path_error='batch paths must be bounded absolute paths without empty, dot or traversal components'
    for value in ['relative','/',str(root)+'/',str(root)+'/./value',str(root)+'/../value',str(root)+'//value',str(path)+'\0x','/'+('a'*4096)]:self.failure(service,dict(base,paths=[value],host='unknown'),path_error)
    self.failure(service,dict(base,paths=[str(path),str(path)],host='unknown'),'read_multiple_files paths must be distinct')
    self.failure(service,dict(base,host='ssh-main'),'unknown host `ssh-main`; call host_list for configured names')
    self.compare(service,root,base)
 def test_4096_byte_component_walk(self):
  # PATH_MAX does not bound this original helper's component-relative walk.
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);prefix=str(root);descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
   try:
    while 4096-len(prefix.encode())-1>200:
     name='d'*200;os.mkdir(name,dir_fd=descriptor);child=os.open(name,os.O_RDONLY|os.O_DIRECTORY,dir_fd=descriptor);os.close(descriptor);descriptor=child;prefix+='/'+name
    name='z'*(4096-len(prefix.encode())-1);target=prefix+'/'+name
    self.assertEqual(len(target.encode()),4096)
    handle=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=descriptor)
    try:os.write(handle,b'whole-file boundary\n')
    finally:os.close(handle)
   finally:os.close(descriptor)
   with shared.Session(self.executable,root) as service:
    service.ready();self.compare(service,root,{'host':'native-local','paths':[target]})

if __name__=='__main__':
 result=unittest.main(exit=False,verbosity=2)
 proof={'schema':'hepta.runtime.native-multi-service-test.v1','status':'pass' if result.result.wasSuccessful() else 'fail','counts':dict(COUNTS,all_actual_elf_responses=shared.COUNTS['elf_requests']),'original_helper_sha256':ORIGINAL_MULTI_SHA}
 if hasattr(MultiServiceTests,'metadata'):
  proof.update(manifest_sha256=hashlib.sha256(MultiServiceTests.manifest.read_bytes()).hexdigest(),executable_sha256=MultiServiceTests.metadata['executable_sha256'])
 if os.environ.get('HIA_MULTI_SERVICE_RESULT'):Path(os.environ['HIA_MULTI_SERVICE_RESULT']).write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
 print(json.dumps(proof,sort_keys=True));raise SystemExit(0 if result.result.wasSuccessful() else 1)
