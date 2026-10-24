# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Fail-closed and terminal/output distinction regression tests; owned temp files only."""
import unittest,tempfile,pathlib,os,json,stat,importlib.util,copy
S=importlib.util.spec_from_file_location('core',pathlib.Path(__file__).resolve().parents[1]/'deploy/inventory_host_readonly.py');C=importlib.util.module_from_spec(S);S.loader.exec_module(C)
class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='hepta-inventory-r3-');self.root=pathlib.Path(self.temp.name);self.fd=C.open_directory(str(self.root));self.count=0
 def tearDown(self):os.close(self.fd);self.temp.cleanup()
 def f(self,b,mode=0o600,name='record.json'):
  p=self.root/name;p.write_bytes(b if isinstance(b,bytes) else json.dumps(b).encode());p.chmod(mode);return p
 def read(self):return C.read_record(self.fd,'record.json',[0])
 def final(self):return {'exit_code':0,'cancelled':False,'timed_out':False,'output_complete':True,'log_bytes':{'stdout':{'seen':3,'stored':3},'stderr':{'seen':0,'stored':0}},'log_errors':{'stdout':None,'stderr':None},'log_truncated':{'stdout':False,'stderr':False}}
 def term(self,v):return C.terminal_receipt('jobs',{},v,{'stdout':3,'stderr':0})
 def test_read_private_regular(self):self.f({'x':1});self.assertEqual(self.read()[0],{'x':1})
 def test_read_readonly_private(self):self.f({'x':1},0o400);self.assertEqual(self.read()[0],{'x':1})
 def test_duplicate_json_keys(self):self.f(b'{"x":1,"x":2}');self.assertRaises(C.Refusal,self.read)
 def test_nan_json_refused(self):self.f(b'{"x":NaN}');self.assertRaises(C.Refusal,self.read)
 def test_wrong_root_type(self):self.f({'x':1});self.assertRaises(OSError,C.open_directory,str(self.root/'record.json'))
 def test_root_symlink_refused(self):p=self.root/'link';p.symlink_to(self.root);self.assertRaises(OSError,C.open_directory,str(p))
 def test_record_symlink_refused(self):self.f({'x':1},name='original');(self.root/'record.json').symlink_to('original');self.assertRaises(OSError,self.read)
 def test_record_hardlink_refused(self):self.f({'x':1});os.link(self.root/'record.json',self.root/'link');self.assertRaises(C.Refusal,self.read)
 def test_group_readable_refused(self):self.f({'x':1},0o640);self.assertRaises(C.Refusal,self.read)
 def test_fifo_nonblocking_refused(self):os.mkfifo(self.root/'record.json',0o600);self.assertRaises(C.Refusal,self.read)
 def test_leaf_traversal_refused(self):self.assertRaises(C.Refusal,C.read_record,self.fd,'../else',[0])
 def test_json_array_refused(self):self.f([]);self.assertRaises(C.Refusal,self.read)
 def test_missing_is_missing_not_empty(self):self.assertRaises(FileNotFoundError,self.read);self.assertEqual(C.optional(self.fd,'record.json',[0]),(None,None))
 def test_large_record_refused(self):self.f(b'x'*(C.CAP+1));self.assertRaises(C.Refusal,self.read)
 def test_global_budget_refused(self):self.f({'x':1});self.assertRaises(C.Refusal,C.read_record,self.fd,'record.json',[64*1024*1024])
 def test_complete_exit_and_size_pass(self):v=self.term(self.final());self.assertEqual(v['state'],'succeeded');self.assertTrue(v['output_verified_by_size_and_receipt'])
 def test_bool_exit_refused(self):v=self.final();v['exit_code']=True;self.assertRaises(C.Refusal,self.term,v)
 def test_string_cancel_flag_refused(self):v=self.final();v['cancelled']='false';self.assertRaises(C.Refusal,self.term,v)
 def test_failed_exit_is_terminal_not_success(self):v=self.final();v['exit_code']=7;self.assertEqual(self.term(v)['state'],'failed')
 def test_cancellation_distinct(self):v=self.final();v['cancelled']=True;self.assertEqual(self.term(v)['state'],'cancelled')
 def test_timeout_distinct(self):v=self.final();v['timed_out']=True;self.assertEqual(self.term(v)['state'],'timed_out')
 def test_legacy_exit_not_complete_output(self):v={'exit_code':0,'cancelled':False,'timed_out':False};o=self.term(v);self.assertEqual(o['state'],'succeeded');self.assertFalse(o['output_verified_by_size_and_receipt'])
 def test_missing_log_not_complete(self):v=C.terminal_receipt('jobs',{},self.final(),{'stdout':None,'stderr':0});self.assertFalse(v['output_verified_by_size_and_receipt'])
 def test_wrong_size_not_complete(self):v=self.final();v['log_bytes']['stdout']['stored']=2;self.assertFalse(self.term(v)['output_verified_by_size_and_receipt'])
 def test_truncated_not_complete(self):v=self.final();v['log_truncated']['stdout']=True;self.assertFalse(self.term(v)['output_verified_by_size_and_receipt'])
 def test_output_error_not_complete(self):v=self.final();v['log_errors']['stdout']='bad';self.assertFalse(self.term(v)['output_verified_by_size_and_receipt'])
 def test_invalid_output_map(self):v=self.final();v['log_bytes']=None;self.assertRaises(C.Refusal,self.term,v)
 def test_pty_real_complete_record(self):v={'state':'exited','exit_code':0,'bytes_seen':3,'bytes_stored':3,'capture_error':None,'output_complete':True};o=C.terminal_receipt('terminals',{},v,{'output':3});self.assertTrue(o['output_verified_by_size_and_receipt'])
 def test_pty_bool_size_not_complete(self):v={'state':'exited','exit_code':0,'bytes_seen':True,'bytes_stored':1,'capture_error':None,'output_complete':True};self.assertFalse(C.terminal_receipt('terminals',{},v,{'output':1})['output_verified_by_size_and_receipt'])
 def test_unfinished_pty_cannot_be_terminal(self):v={'state':'running','exit_code':0};self.assertRaises(C.Refusal,C.terminal_receipt,'terminals',{},v,{})
 def test_names_limit_no_empty_success(self):self.f({});self.assertRaises(C.Refusal,C.bounded_names,self.fd,0)
 def test_target_missing_explicit_row(self):v=C.observe_host({'host':'test','platform':'linux','root':str(self.root),'rows':[{'id':'aa-bb-cc','kind':'jobs','fingerprint':1}]});self.assertFalse(v['all_records_resolved']);self.assertEqual(v['rows'][0]['state'],'unknown')

 def test_strict_group_writable_root_still_refused(self):
  self.root.chmod(0o770);self.assertRaises(C.Refusal,C.open_directory,str(self.root));self.root.chmod(0o700)
 def test_observation_root_does_not_claim_trust(self):
  self.root.chmod(0o770);v=C.observe_host({'host':'test','platform':'linux','root':str(self.root),'rows':[]});self.assertTrue(v['root_group_writable']);self.assertFalse(v['source_root_integrity_qualified']);self.root.chmod(0o700)
 def test_world_writable_root_still_refused_for_observation(self):
  self.root.chmod(0o777);self.assertRaises(C.Refusal,C.open_directory,str(self.root),True);self.root.chmod(0o700)
 def test_string_fingerprint_matches_native_contract(self):
  rid='aa-bb-cc';d=self.root/'jobs'/rid;d.mkdir(parents=True,mode=0o700)
  for name,v in [('request.json',{'job_id':rid,'request_fingerprint':'0'*64}),('exit.json',self.final())]:
   p=d/name;p.write_text(json.dumps(v));p.chmod(0o600)
  for name,b in [('stdout.log',b'abc'),('stderr.log',b'')]:p=d/name;p.write_bytes(b);p.chmod(0o600)
  v=C.observe_host({'host':'test','platform':'linux','root':str(self.root),'rows':[{'id':rid,'kind':'jobs','fingerprint':'0'*64}]});self.assertEqual(v['rows'][0]['state'],'succeeded')
 def test_legacy_nonhex64_terminal_id_matches_real_contract(self):
  rid='dpty-aa-bb-cc';d=self.root/'terminals'/rid;d.mkdir(parents=True,mode=0o700)
  v={'state':'exited','exit_code':0,'bytes_seen':0,'bytes_stored':0,'capture_error':None,'output_complete':True}
  for name,obj in [('request.json',{'session_id':rid}),('exit.json',v)]:p=d/name;p.write_text(json.dumps(obj));p.chmod(0o600)
  p=d/'output.log';p.write_bytes(b'');p.chmod(0o600)
  v=C.observe_host({'host':'test','platform':'linux','root':str(self.root),'rows':[{'id':rid,'kind':'terminals'}]});self.assertEqual(v['rows'][0]['state'],'exited')

if __name__=='__main__':unittest.main()
