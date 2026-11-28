#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual native ELF file_info results against unchanged original helpers."""
from __future__ import annotations
import hashlib,json,os,random,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_local_service as shared

ROOT=shared.ROOT
METADATA_SHA='24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3'
COUNTS={'info_requests':0,'original_info_comparisons':0,'original_failure_comparisons':0,
        'parameter_refusals':0,'domain_refusals':0,'acl_comparisons':0}

class InfoServiceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  metadata=ROOT/'src/mcp/runtime/file_metadata.py'
  assert hashlib.sha256(metadata.read_bytes()).hexdigest()==METADATA_SHA
  shared.NativeServiceTests.setUpClass()
  cls.manifest=shared.NativeServiceTests.manifest
  cls.metadata=shared.NativeServiceTests.metadata
  cls.executable=shared.NativeServiceTests.executable
  cls.original=shared.NativeServiceTests.original
  assert len(cls.metadata['profile'])==7
  assert cls.metadata['profile'][0]['call_mask']==126
  assert cls.metadata['profile'][6]['flags']==1
  assert cls.metadata['profile'][6]['call_mask']==30
  source=Path(os.environ.get('HIA_INFO_SERVICE_SOURCE',ROOT/'native/file_info_service.hepta'))
  assert hashlib.sha256(source.read_bytes()).hexdigest()==cls.metadata['members'][6]['source_sha256']

 @classmethod
 def tearDownClass(cls):
  assert hashlib.sha256((ROOT/'src/mcp/runtime/file_metadata.py').read_bytes()).hexdigest()==METADATA_SHA
  assert hashlib.sha256((ROOT/'src/mcp/runtime/binary_file.py').read_bytes()).hexdigest()==shared.ORIGINAL_SHA

 def call(self,service,args,raw=False):
  result=service.tool('file_info',args,identity='info 雪"\n',raw=raw)
  COUNTS['info_requests']+=1
  return result

 def compare(self,service,root,path):
  expected=self.original.main({'op':'info','root':str(root),'path':str(path)})
  failed,text=self.call(service,{'host':'native-local','path':str(path)})
  self.assertFalse(failed,text)
  self.assertEqual(json.loads(text),expected)
  self.assertEqual(text,json.dumps(expected,ensure_ascii=False,sort_keys=True,separators=(',',':')))
  COUNTS['original_info_comparisons']+=1
  return expected

 def test_complete_hashes_and_original_results(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);rng=random.Random(0xF11E1AF0)
   sizes=[0,1,63,64,65,4095,4096,4097,65535,65536,65537,(1<<20)-1,1<<20,(1<<20)+1,(5<<20)+17]
   paths=[]
   for index,size in enumerate(sizes):
    path=root/(str(index)+('"\\\n\t雪😀' if index==4 else ''))
    path.write_bytes(rng.randbytes(size));paths.append(path)
   with shared.Session(self.executable,root) as service:
    service.ready()
    catalog=service.call(shared.req('tools/list'))['result']['tools']
    self.assertEqual([t['name'] for t in catalog],['host_list','binary_read','read_multiple_files','file_info'])
    info=catalog[3]
    self.assertEqual(info['title'],'file_info')
    self.assertEqual(info['annotations'],{'readOnlyHint':True,'destructiveHint':False,'idempotentHint':True,'openWorldHint':True})
    for path in paths:self.compare(service,root,path)
    link=root/'hardlink';os.link(paths[4],link)
    for path in [link,str(root)+'/./0',str(root)+'//1']:self.compare(service,root,path)
    for mode in [0o400,0o600,0o640,0o754,0o4755,0o2755,0o1755]:
     os.chmod(paths[5],mode);self.compare(service,root,paths[5])
    good=root/'text';good.write_text('shared IO owner 雪\n',encoding='utf-8')
    for tool,args in [('binary_read',{'host':'native-local','path':str(good)}),
                      ('read_multiple_files',{'host':'native-local','paths':[str(good)]}),
                      ('host_list',{})]:
     self.assertFalse(service.tool(tool,args)[0]);self.compare(service,root,good)

 def test_linux_xattrs_and_acl_summary(self):
  # This environment's /tmp mount lacks POSIX ACLs; the workspace filesystem
  # supports them. Select an owned fixture directory without skipping ACL proof.
  with tempfile.TemporaryDirectory(prefix='hia-info-acl-',dir=os.environ.get('HIA_INFO_FIXTURE_ROOT',str(ROOT))) as directory:
   root=Path(directory);path=root/'metadata';path.write_bytes(b'binary\xff\0payload')
   initial_attrs={name:os.getxattr(path,name) for name in os.listxattr(path)}
   values={'user.z-last':b'last','user.empty':b'','user.binary':bytes(range(256)),
           'user.quote"\\\n\t雪😀':b'PRIVATE-XATTR-VALUE-NOT-RETURNED',
           'user.a-first':b'a'*2048}
   for name,value in values.items():os.setxattr(path,name,value)
   with shared.Session(self.executable,root) as service:
    service.ready();result=self.compare(service,root,path)
    expected_attrs=dict(initial_attrs,**values)
    self.assertEqual(result['metadata']['xattr_names'],sorted(expected_attrs))
    self.assertEqual(result['metadata']['xattr_sha256'],{k:hashlib.sha256(v).hexdigest() for k,v in expected_attrs.items()})
    self.assertEqual(result['metadata']['acl_sha256'],hashlib.sha256(expected_attrs.get('system.posix_acl_access',b'')).hexdigest())
    self.assertNotIn('PRIVATE-XATTR-VALUE-NOT-RETURNED',json.dumps(result))
    for name in list(values)[::2]:os.removexattr(path,name);self.compare(service,root,path)
    # A named-user ACL remains an actual Linux xattr, unlike a mode-only ACL
    # which the kernel may collapse to permission bits.
    acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,identity) for tag,perm,identity in
       [(1,6,0xffffffff),(2,4,os.getuid()),(4,4,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)])
    os.setxattr(path,'system.posix_acl_access',acl)
    actual_acl=os.getxattr(path,'system.posix_acl_access')
    result=self.compare(service,root,path)
    self.assertEqual(result['metadata']['acl_sha256'],hashlib.sha256(actual_acl).hexdigest())
    COUNTS['acl_comparisons']+=1

 def test_typed_parameters_and_policy_order(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);path=root/'value';path.write_bytes(b'value')
   args={'host':'native-local','path':str(path)}
   with shared.Session(self.executable,root) as service:
    service.ready()
    invalid=[{},dict(args,host=None),dict(args,path=None),dict(args,path=True),
             dict(args,host=[]),dict(args,path={}),dict(args,offset=0),dict(args,limit=1),
             dict(args,expected_version='x'),dict(args,root='/'),dict(args,op='info'),
             dict(args,interpreter='python3'),dict(args,ssh_target='elsewhere')]
    for item in invalid:
     response=self.call(service,item,raw=True)
     self.assertEqual(response['error']['code'],-32602,response);COUNTS['parameter_refusals']+=1
    for item,expected in [
       (dict(args,host='remote-alias',path='relative'),'unknown host `remote-alias`; call host_list for configured names'),
       (dict(args,path='relative'),'remote file access requires an absolute target path'),
       (dict(args,path=str(root)+'/../value'),'remote path traversal is not allowed'),
       (dict(args,path=str(root.parent/'outside-info')),f'path `{root.parent / "outside-info"}` is outside configured read roots on host `native-local`'),
       (dict(args,path=str(root)),'capability root and runtime sidecars are not file targets'),
       (dict(args,path=str(root/'.hepta-info')),'capability root and runtime sidecars are not file targets'),
       (dict(args,path=str(path)+'\0suffix'),'embedded null byte')]:
     failed,text=self.call(service,item);self.assertTrue(failed);self.assertEqual(text,expected);COUNTS['domain_refusals']+=1
    self.compare(service,root,path)

 def test_original_failures_and_recovery(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);good=root/'good';good.write_bytes(b'recoverable')
   missing=root/'missing';link=root/'symbolic';link.symlink_to(good)
   folder=root/'folder';folder.mkdir();fifo=root/'fifo';os.mkfifo(fifo)
   with shared.Session(self.executable,root) as service:
    service.ready()
    for path,expected in [(missing,'native local open failed (errno 2)'),
                          (link,'native local open failed (errno 40)'),
                          (folder,'invalid regular file or private sidecar'),
                          (fifo,'invalid regular file or private sidecar')]:
     with self.assertRaises((ValueError,OSError)):
      self.original.main({'op':'info','root':str(root),'path':str(path)})
     COUNTS['original_failure_comparisons']+=1
     failed,text=self.call(service,{'host':'native-local','path':str(path)})
     self.assertTrue(failed);self.assertEqual(text,expected);COUNTS['domain_refusals']+=1
     self.compare(service,root,good)

 def test_4096_byte_component_walk(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);prefix=str(root);descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
   try:
    while 4096-len(prefix.encode())-1>200:
     name='d'*200;os.mkdir(name,dir_fd=descriptor)
     child=os.open(name,os.O_RDONLY|os.O_DIRECTORY,dir_fd=descriptor)
     os.close(descriptor);descriptor=child;prefix+='/'+name
    name='z'*(4096-len(prefix.encode())-1);target=prefix+'/'+name
    self.assertEqual(len(target.encode()),4096)
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=descriptor)
    try:os.write(fd,b'full fingerprint at path boundary\xff')
    finally:os.close(fd)
   finally:os.close(descriptor)
   with shared.Session(self.executable,root) as service:
    service.ready();self.compare(service,root,target)
    failed,text=self.call(service,{'host':'native-local','path':target+'x'})
    self.assertTrue(failed);self.assertEqual(text,'path exceeds the native-local 4096-byte limit')
    COUNTS['domain_refusals']+=1

if __name__=='__main__':
 result=unittest.main(exit=False,verbosity=2)
 proof={'schema':'hepta.runtime.native-info-service-test.v1','status':'pass' if result.result.wasSuccessful() else 'fail',
        'counts':dict(COUNTS,all_actual_elf_responses=shared.COUNTS['elf_requests']),
        'original_helper_sha256':shared.ORIGINAL_SHA,'original_metadata_sha256':METADATA_SHA}
 if hasattr(InfoServiceTests,'metadata'):
  proof.update(manifest_sha256=hashlib.sha256(InfoServiceTests.manifest.read_bytes()).hexdigest(),
               executable_sha256=InfoServiceTests.metadata['executable_sha256'])
 if os.environ.get('HIA_INFO_SERVICE_RESULT'):Path(os.environ['HIA_INFO_SERVICE_RESULT']).write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
 print(json.dumps(proof,sort_keys=True));raise SystemExit(0 if result.result.wasSuccessful() else 1)
