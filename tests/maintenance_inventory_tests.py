#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only inventory tests; no power or checkpoint operation is executed."""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('maintenance',ROOT/'deploy/maintenance_inventory.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

def entry(pid,parent=1,uid=1000,ticks=20):
    return {'pid':pid,'ppid':parent,'uids':[uid]*4,'start_ticks':ticks,'state':'S','comm':'fixture'}

def pipe(fd,ident='pipe:[123]',access=0):return {'fd':fd,'kind':'pipe','access':access,'position':0,'resource':ident}


class MaintenanceInventory(unittest.TestCase):
    def table(self):return {100:entry(100),101:entry(101,100),200:entry(200)}
    def invoke(self,descriptors,records=None,unknown=None):
        records=records or self.table()
        with mock.patch.object(M,'process_table',return_value=(records,unknown or [])),mock.patch.object(M,'process_identity',side_effect=lambda pid,proc:records[pid]),mock.patch.object(M,'descriptor_inventory',side_effect=lambda pid,proc:descriptors[pid]):
            return M.resource_report(100,uid=1000)
    def test_family_includes_children_without_mutation(self):
        self.assertEqual(M.family(self.table(),100),[100,101])
        result=self.invoke({100:[pipe(3)],101:[pipe(4,access=1)],200:[]})
        self.assertEqual(result['process_count'],2);self.assertEqual(result['external_descriptor_owners'],[])
        self.assertIn('native_process_tree_capture_not_implemented',result['limitations'])
        self.assertFalse(result['migration_authorized']);self.assertFalse(result['processes_signalled'])
    def test_external_owner_identity_and_access_are_reported(self):
        result=self.invoke({100:[pipe(0)],101:[],200:[pipe(9,access=1)]})
        owner=result['external_descriptor_owners'][0]
        self.assertEqual(owner['identity']['pid'],200);self.assertEqual(owner['fd'],9);self.assertEqual(owner['access'],1)
        self.assertIn('external_resource_owners_require_explicit_coordination',result['limitations'])
    def test_permission_failure_never_means_no_external_owner(self):
        rows=self.table()
        def fds(pid,proc):
            if pid==200:raise PermissionError('fixture unreadable')
            return [pipe(0)] if pid==100 else []
        with mock.patch.object(M,'process_table',return_value=(rows,[])),mock.patch.object(M,'process_identity',side_effect=lambda pid,proc:rows[pid]),mock.patch.object(M,'descriptor_inventory',side_effect=fds):
            result=M.resource_report(100,uid=1000)
        self.assertFalse(result['ownership_scan_complete']);self.assertEqual(result['unavailable_count'],1)
    def test_reused_pid_marks_observation_unstable(self):
        rows=self.table()
        with mock.patch.object(M,'process_table',return_value=(rows,[])),mock.patch.object(M,'descriptor_inventory',return_value=[]),mock.patch.object(M,'process_identity',side_effect=lambda pid,proc:{**rows[pid],'start_ticks':999}):
            result=M.resource_report(100,uid=1000)
        self.assertFalse(result['observation_stable']);self.assertFalse(result['migration_authorized'])
    def test_other_uid_or_mixed_credentials_refused(self):
        rows=self.table();rows[101]=entry(101,100,uid=0)
        with self.assertRaises(PermissionError):self.invoke({100:[],101:[],200:[]},rows)
        rows[101]=entry(101,100);rows[101]['uids'][1]=0
        with self.assertRaises(PermissionError):self.invoke({100:[],101:[],200:[]},rows)
    def test_tree_size_bound_and_absent_root(self):
        rows={p:entry(p,100) for p in range(101,167)};rows[100]=entry(100)
        with self.assertRaisesRegex(ValueError,'budget'):M.family(rows,100)
        with self.assertRaises(ValueError):M.family(rows,999)
    def test_regular_file_paths_and_bytes_are_not_returned(self):
        result=self.invoke({100:[{'fd':1,'kind':'regular_file','access':1,'position':17}],101:[],200:[]})
        self.assertFalse(result['resource_bytes_read']);self.assertNotIn('/home/',json.dumps(result))
        self.assertEqual(result['members'][0]['descriptors'][0]['position'],17)
    def test_socket_and_gpu_require_separate_contract(self):
        result=self.invoke({100:[{'fd':4,'kind':'gpu_device','access':2,'position':0}],101:[],200:[]})
        self.assertIn('unsupported_or_unclassified_external_kernel_resources',result['limitations'])
    def test_failed_command_is_unavailable_not_empty_success(self):
        with mock.patch.object(M.subprocess,'run',side_effect=PermissionError('fixture')):
            self.assertFalse(M.command_json(['none'])['available'])
    def test_current_process_identity_reads_only_proc_metadata(self):
        identity=M.process_identity(os.getpid())
        self.assertEqual(identity['pid'],os.getpid());self.assertEqual(identity['uids'],[os.getuid()]*4)
    def test_idle_report_never_authorizes_unverified_reboot(self):
        with tempfile.TemporaryDirectory() as t:
            proc=pathlib.Path(t);(proc/'sys/kernel/random').mkdir(parents=True);(proc/'sys/kernel/random/boot_id').write_text('fixture-boot')
            with mock.patch.object(M,'process_table',return_value=({},[])),mock.patch.object(M,'command_json',return_value={'available':True,'value':[]}):
                result=M.maintenance_report(proc)
        self.assertFalse(result['safe_reboot_proven']);self.assertFalse(result['power_action_authorized'])

    def test_descriptor_rebinding_is_not_mistaken_for_stable_pid(self):
        rows={100:entry(100)};calls=[0]
        def fds(pid,proc):
            calls[0]+=1
            return [pipe(3,'pipe:[123]' if calls[0]==1 else 'pipe:[456]')]
        with mock.patch.object(M,'process_table',return_value=(rows,[])),mock.patch.object(M,'process_identity',return_value=rows[100]),mock.patch.object(M,'descriptor_inventory',side_effect=fds):
            result=M.resource_report(100,uid=1000)
        self.assertTrue(result['observation_stable']);self.assertFalse(result['descriptor_bindings_stable'])
        self.assertIn('descriptor_binding_changed_during_observation',result['limitations'])


    def test_one_disappearing_descriptor_does_not_hide_known_owned_descriptors(self):
        with tempfile.TemporaryDirectory() as t:
            proc=pathlib.Path(t);root=proc/'100';(root/'fd').mkdir(parents=True);(root/'fdinfo').mkdir()
            (root/'fd/3').symlink_to('/dev/null');(root/'fd/4').symlink_to('/definitely-missing-hepta-test-path')
            for n in (3,4):(root/'fdinfo'/str(n)).write_text('pos: 0\nflags: 0100000\n')
            descriptors=M.descriptor_inventory(100,proc)
        self.assertEqual(descriptors[0]['kind'],'basic_device');self.assertEqual(descriptors[1]['kind'],'unavailable')



if __name__=='__main__':unittest.main(verbosity=2)
