#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Signal/state regressions without CRIU or real-user process side effects."""
import importlib.util
import json
import os
import pathlib
import signal
import tempfile
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('checkpoint_v2',ROOT/'src/mcp/runtime/checkpoint_host.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
WHO={'pid':123,'uid':1000,'boot_id':'same-boot','start_ticks':55}


class CheckpointLifecycle(unittest.TestCase):
    def state(self,kind='restored_stopped'):
        return {'state':kind,'restored_identity':dict(WHO),'images':{'memory.img':'private-hash'},'file_pins':{'private-path':'private-data'}}
    def invoke(self,state,q,actual=None,kernel='T',signal_error=None):
        with mock.patch.object(C.os,'pidfd_open',return_value=88) as opening,mock.patch.object(C.os,'close') as closing,mock.patch.object(C,'identity',return_value=actual or dict(WHO)),mock.patch.object(C,'kernel_state',return_value=kernel),mock.patch.object(C,'save') as saving,mock.patch.object(C.signal,'pidfd_send_signal',side_effect=signal_error) as sending:
            result=C.resume(state,q,pathlib.Path('/never-written'))
            return result,opening.call_count,sending.call_args_list,saving.call_count,closing.call_count
    def q(self):return {'acknowledge_resume':True,'expected_identity':dict(WHO)}
    def test_restored_stopped_is_not_reported_running(self):
        with mock.patch.object(C,'identity',return_value=WHO),mock.patch.object(C,'kernel_state',return_value='T'):
            result=C.public_state(self.state())
        self.assertTrue(result['requires_explicit_resume']);self.assertEqual(result['restored_kernel_state'],'T')
        self.assertNotIn('images',result);self.assertNotIn('file_pins',result);self.assertFalse(result['images_exported'])
    def test_missing_acknowledgement_cannot_send_signal(self):
        with mock.patch.object(C.signal,'pidfd_send_signal') as send:
            with self.assertRaises(ValueError):C.resume(self.state(),{'expected_identity':WHO},pathlib.Path('/never-written'))
            send.assert_not_called()
    def test_stale_expected_identity_cannot_open_pid(self):
        with mock.patch.object(C.os,'pidfd_open') as opening:
            with self.assertRaisesRegex(ValueError,'stale'):C.resume(self.state(),{**self.q(),'expected_identity':{**WHO,'start_ticks':56}},pathlib.Path('/never-written'))
            opening.assert_not_called()
    def test_actual_reused_pid_is_rejected_before_signal(self):
        with self.assertRaisesRegex(ValueError,'stale'):self.invoke(self.state(),self.q(),actual={**WHO,'start_ticks':56})
    def test_resume_intent_then_signal_then_commit(self):
        state=self.state();result,opened,signals,writes,closed=self.invoke(state,self.q())
        self.assertEqual(result['state'],'resumed');self.assertFalse(result['reused'])
        self.assertEqual((opened,len(signals),writes,closed),(1,1,2,1))
        self.assertEqual(signals[0].args,(88,signal.SIGCONT))
    def test_confirmed_resume_replay_never_signals_again(self):
        result,opened,signals,writes,closed=self.invoke(self.state('resumed'),self.q())
        self.assertTrue(result['reused']);self.assertEqual((opened,len(signals),writes,closed),(0,0,0,0))
    def test_uncertain_resume_replay_never_signals_again(self):
        with mock.patch.object(C.signal,'pidfd_send_signal') as send:
            with self.assertRaisesRegex(ValueError,'reconciliation'):C.resume(self.state('resume_requested'),self.q(),pathlib.Path('/never-written'))
            send.assert_not_called()
    def test_signal_failure_preserves_uncertain_intent(self):
        state=self.state()
        with self.assertRaises(ProcessLookupError):self.invoke(state,self.q(),signal_error=ProcessLookupError('fixture vanished'))
        self.assertEqual(state['state'],'resume_requested')
    def test_external_resumption_not_overridden(self):
        with self.assertRaisesRegex(ValueError,'not stopped'):self.invoke(self.state(),self.q(),kernel='S')
    def test_regular_pin_checks_content_metadata_and_fifo(self):
        with tempfile.TemporaryDirectory(prefix='hepta-snapshot-pin-') as t:
            p=pathlib.Path(t)/'file';p.write_bytes(b'abc');before=C.pin(p);p.write_bytes(b'abd');after=C.pin(p)
            self.assertNotEqual(before,after)
            f=pathlib.Path(t)/'fifo';os.mkfifo(f)
            with self.assertRaises(ValueError):C.pin(f)
    def test_state_publication_is_exact_private_json(self):
        with tempfile.TemporaryDirectory(prefix='hepta-snapshot-state-') as t:
            p=pathlib.Path(t)/'state.json';C.save(p,{'state':'restored_stopped'})
            self.assertEqual(json.loads(p.read_text()),{'state':'restored_stopped'});self.assertEqual(p.stat().st_mode&0o777,0o600)
            C.save(p,{'state':'resumed'});self.assertEqual(json.loads(p.read_text()),{'state':'resumed'})

    def test_pipe_both_ends_local_does_not_hide_external_duplicate(self):
        with tempfile.TemporaryDirectory(prefix='hepta-fd-owner-') as t:
            root=pathlib.Path(t)
            for pid in ('123','456','789'):(root/pid/'fd').mkdir(parents=True)
            (root/'123/fd/3').symlink_to('pipe:[99]')
            (root/'123/fd/4').symlink_to('pipe:[99]')
            (root/'456/fd/8').symlink_to('pipe:[99]')
            (root/'789/fd/1').symlink_to('pipe:[77]')
            self.assertEqual(C.external_pipe_owners({'pipe:[99]'},123,root),[{'pid':456,'fd':8}])
            (root/'456/fd/8').unlink()
            self.assertEqual(C.external_pipe_owners({'pipe:[99]'},123,root),[])



if __name__=='__main__':unittest.main(verbosity=2)
