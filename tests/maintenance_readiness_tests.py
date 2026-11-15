#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Signed maintenance evidence must fail closed and never itself authorize reboot."""
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('maintenance_readiness',ROOT/'deploy/maintenance_readiness.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class MaintenanceReadiness(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-maintenance-readiness-');self.root=pathlib.Path(self.temp.name)
        self.key=Ed25519PrivateKey.generate();public=self.key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        self.public=self.root/'public.pem';self.public.write_bytes(public);self.public.chmod(0o600)
        self.artifact=self.root/'checkpoint.bin';self.artifact.write_bytes(b'durable fixture checkpoint')
        self.resource_id='process:4242';self.binding={'pid':4242,'ppid':1,'start_ticks':12345,'uids':[1000]*4,'comm':'fixture'}
        self.resources={self.resource_id:self.binding};self.now=datetime.datetime(2026,10,7,4,0,tzinfo=datetime.timezone.utc)
        self.boot='fixture-boot';self.adapter='fixture-native-adapter';self.fence='fixture-fence-01'
        self.state_digest=hashlib.sha256(b'logical application state').hexdigest()
        self.checkpoint_sha=hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        observed=(self.now-datetime.timedelta(seconds=5)).isoformat();expires=(self.now+datetime.timedelta(seconds=30)).isoformat()
        common={'version':1,'resource_id':self.resource_id,'identity_digest':M.digest(self.binding),'host_boot_id':self.boot,
                'observed_at':observed,'expires_at':expires,'adapter':self.adapter,'checkpoint_sha256':self.checkpoint_sha,
                'quiescence_fence_id':self.fence}
        self.checkpoint={**common,'kind':'HeptaBusinessCheckpointReceipt','status':'quiesced-durable-checkpoint',
                         'checkpoint_artifact_path':str(self.artifact),'state_digest':self.state_digest}
        self.restore={**common,'kind':'HeptaBusinessRestoreReceipt','status':'isolated-recovery-verified',
                      'observed_at':(self.now-datetime.timedelta(seconds=3)).isoformat(),
                      'expected_state_digest':self.state_digest,'recovered_state_digest':self.state_digest}
        self.check_ref=self.envelope('checkpoint.json',self.checkpoint)
        self.restore_ref=self.envelope('restore.json',self.restore)
        self.trust={'version':1,'keys':{'fixture-key':{'resource_ids':[self.resource_id],'adapters':[self.adapter],
                    'public_key_path':str(self.public),'public_key_sha256':hashlib.sha256(public).hexdigest()}}}
        self.snapshot=self.inventory();self.current=self.inventory()
        self.manifest={'version':1,'boot_id':self.boot,'inventory_identity_digest':M.digest(self.resources),
                       'resources':{self.resource_id:{'checkpoint':self.check_ref,'restore':self.restore_ref}}}

    def tearDown(self):self.temp.cleanup()

    def inventory(self):
        return {'version':1,'hostname':'fixture-host','boot_id':self.boot,'observed_at':(self.now-datetime.timedelta(seconds=4)).isoformat(),
                'resources':self.resources,'identity_digest':M.digest(self.resources),'inventory_failures':[],
                'scope':'fixture','observer_pid':999,'mode':'observe_only','safe_reboot_proven':False,'power_action_authorized':False}

    def envelope(self,name,payload,sign=True):
        signature=self.key.sign(M.canonical(payload)) if sign else b'not a valid signature'
        data={'key_id':'fixture-key','payload':payload,'signature_base64':base64.b64encode(signature).decode()}
        path=self.root/name;path.write_text(json.dumps(data));path.chmod(0o600)
        return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

    def evaluate(self,**changes):
        values={'snapshot':self.snapshot,'current':self.current,'manifest':self.manifest,'trust':self.trust,'now':self.now,'max_age':60}
        values.update(changes);return M.evaluate(**values)

    def test_valid_signed_evidence_is_complete_but_never_authorizes_reboot(self):
        result=self.evaluate()
        self.assertEqual(result['blockers'],[])
        self.assertEqual(result['business_evidence_status'],'signed_evidence_complete_under_configured_trust')
        self.assertEqual(result['resources'][0]['status'],'signed_evidence_verified')
        self.assertFalse(result['safe_reboot_proven']);self.assertFalse(result['power_action_authorized'])
        self.assertFalse(result['controller_reboot_executed'])

    def test_invalid_signature_blocks_resource(self):
        bad=self.envelope('bad-restore.json',self.restore,sign=False)
        manifest=json.loads(json.dumps(self.manifest));manifest['resources'][self.resource_id]['restore']=bad
        result=self.evaluate(manifest=manifest)
        self.assertIn('business_resources_have_unresolved_restart_evidence',result['blockers'])
        self.assertIn('receipt_signature_invalid',result['resources'][0]['blockers'])

    def test_stale_receipt_and_expired_fence_fail_closed(self):
        stale={**self.restore,'observed_at':(self.now-datetime.timedelta(minutes=5)).isoformat(),
               'expires_at':(self.now-datetime.timedelta(minutes=4)).isoformat()}
        ref=self.envelope('stale.json',stale);manifest=json.loads(json.dumps(self.manifest));manifest['resources'][self.resource_id]['restore']=ref
        result=self.evaluate(manifest=manifest)
        self.assertIn('receipt_stale_or_fence_expired',result['resources'][0]['blockers'])

    def test_boot_or_resource_identity_drift_blocks_even_with_valid_receipts(self):
        current=json.loads(json.dumps(self.current));current['boot_id']='different';current['resources'][self.resource_id]['start_ticks']+=1
        current['identity_digest']=M.digest(current['resources'])
        result=self.evaluate(current=current)
        self.assertIn('host_boot_identity_changed',result['blockers'])
        self.assertIn('business_resource_identity_drift',result['blockers'])

    def test_changed_checkpoint_artifact_is_rejected(self):
        self.artifact.write_bytes(b'changed after signed receipt')
        result=self.evaluate()
        self.assertIn('checkpoint_artifact_hash_mismatch',result['resources'][0]['blockers'])

    def test_signer_must_be_bound_to_both_resource_and_adapter(self):
        for trust in (
            {'version':1,'keys':{'fixture-key':{**self.trust['keys']['fixture-key'],'resource_ids':['other']}}},
            {'version':1,'keys':{'fixture-key':{**self.trust['keys']['fixture-key'],'adapters':['other']}}},
        ):
            result=self.evaluate(trust=trust)
            self.assertIn('resource_adapter_signer_not_trusted',result['resources'][0]['blockers'])

    def test_checkpoint_restore_artifact_fence_and_state_must_match(self):
        for key,value in [('checkpoint_sha256','0'*64),('quiescence_fence_id','other'),('recovered_state_digest','0'*64)]:
            restore={**self.restore,key:value};ref=self.envelope('mismatch-'+key+'.json',restore)
            manifest=json.loads(json.dumps(self.manifest));manifest['resources'][self.resource_id]['restore']=ref
            result=self.evaluate(manifest=manifest)
            self.assertTrue(result['resources'][0]['blockers'])

    def test_inventory_failures_and_staleness_remain_blockers(self):
        current=json.loads(json.dumps(self.current));current['inventory_failures']=['permission denied']
        current['observed_at']=(self.now-datetime.timedelta(minutes=2)).isoformat()
        result=self.evaluate(current=current)
        self.assertIn('inventory_incomplete',result['blockers']);self.assertIn('inventory_observation_stale',result['blockers'])

    def test_caller_ready_boolean_cannot_be_smuggled_into_manifest(self):
        manifest={**self.manifest,'safe_reboot_proven':True}
        result=self.evaluate(manifest=manifest)
        self.assertIn('manifest_schema_invalid',result['blockers']);self.assertFalse(result['safe_reboot_proven'])

    def test_duplicate_json_keys_and_symlink_evidence_are_not_accepted(self):
        duplicate=self.root/'duplicate.json';duplicate.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError,'duplicate_json_key'):M.read_object(duplicate)
        link=self.root/'link.json';link.symlink_to(self.root/'checkpoint.json')
        with self.assertRaises(OSError):M.read_object(link)

    def test_max_age_is_bounded(self):
        with self.assertRaisesRegex(ValueError,'max_age'):self.evaluate(max_age=0)
        with self.assertRaisesRegex(ValueError,'max_age'):self.evaluate(max_age=301)


if __name__=='__main__':unittest.main(verbosity=2)
