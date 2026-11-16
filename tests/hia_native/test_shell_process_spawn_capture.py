"""Regression for a real failed-spawn observer race, without starting a process.

CI 43815671684 attempt 2 retained empty original descriptors for the oversized
exec argument. The original controller accepted that observation; the strong
reader incorrectly required every observed descriptor to imply a child.
"""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('shell_spawn_capture_reader',ROOT/'scripts/hia_native_shell_process_evidence.py')
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)

class SpawnCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.actual=Path(self.temporary.name);self.declared=Path('/qualified/oversized_exec_argument')
        (self.actual/'original/retained').mkdir(parents=True)
        (self.actual/'native/capture').mkdir(parents=True)
        self.prepared={'definition':{'name':'oversized_exec_argument','spawn_errno':7}}
        self.native={'child_pid':None};self.receipt={'pid':5007}
        self.captures={'stdout':b'','stderr':b''}
        raw={'observed':True,'complete_read_from_original_file_descriptors':True,
             'original_paths_mutated_by_observer':False,'source_paths_exist':{'stdout':False,'stderr':False}}
        for stream in ('stdout','stderr'):
            (self.actual/'original/retained'/(stream+'.bin')).write_bytes(b'')
            (self.actual/'native/capture'/(stream+'.log')).write_bytes(b'')
            raw[stream+'_path']=str(self.declared/'original/retained'/(stream+'.bin'))
            raw[stream+'_source_path']=str(self.declared/'tmp/octofs-jobs-5007'/('5007-1.'+stream+'.log'))
            raw[stream+'_bytes']=0
        self.events=[{'event':'foreground','ok':False,'error':'Failed to spawn command: Argument list too long (os error 7)',
                      'os_error_from_message':7,'exit_code_from_owner_result':None},
                     {'event':'final','outcome':'error','callback_count':0,'pid':None,'child_reaped_observed':None,
                      'tracker_pids':[],'implicit_shutdown_performed':False,'original_owner_bodies_changed':False,
                      'raw_wait_status_observable':False,'raw_wait_status':None,'raw_capture':raw}]
    def project(self):
        return reader.original_projection(self.prepared,self.native,self.events,self.receipt,
                                          self.actual,self.declared,self.captures)
    def reject(self):
        with self.assertRaises(reader.EvidenceError):self.project()
    def test_observed_empty_descriptors_are_complete_without_child(self):
        result,captures=self.project()
        self.assertEqual(result['status'],'PASS');self.assertIsNone(result['original_pid'])
        self.assertIsNone(result['native_pid']);self.assertEqual(captures,{'stdout':b'','stderr':b''})
        self.assertTrue(result['capture_comparison']['observed'])
        self.assertEqual(set(result['capture_comparison']['streams']),{'stdout','stderr'})
    def test_unobserved_failure_still_has_no_capture_claim(self):
        self.events[-1]['raw_capture']={'observed':False,'source_paths_exist':None,'stdout_bytes':None,
                                      'stderr_bytes':None,'stdout_path':None,'stderr_path':None}
        result,captures=self.project();self.assertFalse(result['capture_comparison']['observed']);self.assertEqual(captures,{})
    def test_incomplete_descriptor_read_is_rejected(self):
        self.events[-1]['raw_capture']['complete_read_from_original_file_descriptors']=False;self.reject()
    def test_observer_mutation_is_rejected(self):
        self.events[-1]['raw_capture']['original_paths_mutated_by_observer']=True;self.reject()
    def test_nonempty_output_is_rejected_even_when_both_sides_agree(self):
        (self.actual/'original/retained/stdout.bin').write_bytes(b'x');self.captures['stdout']=b'x'
        self.events[-1]['raw_capture']['stdout_bytes']=1;self.reject()
    def test_incorrect_complete_size_is_rejected(self):
        self.events[-1]['raw_capture']['stdout_bytes']=1;self.reject()
    def test_retained_original_path_is_rejected(self):
        self.events[-1]['raw_capture']['source_paths_exist']['stdout']=True;self.reject()
    def test_different_source_path_is_rejected(self):
        self.events[-1]['raw_capture']['stdout_source_path']='/different';self.reject()
    def test_fabricated_child_is_rejected(self):
        self.events[-1]['pid']=1;self.reject()
    def test_fabricated_reap_is_rejected(self):
        self.events[-1]['child_reaped_observed']=True;self.reject()
    def test_capture_ready_for_failed_spawn_is_rejected(self):
        self.events.insert(0,{'event':'capture_ready','pid':1});self.reject()
    def test_incorrect_errno_is_rejected(self):
        self.events[0]['os_error_from_message']=2;self.reject()

if __name__=='__main__':unittest.main()
