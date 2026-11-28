"""Adversarial qualification of importing already-recovered bytes for one original job."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kaggle_jobs import KaggleAdapter, digest
from kaggle_transport import AdapterError, RemoteError
from kaggle_create_only import CreateOnlyKaggleAdapter
from test_jobs import FakeTransport


class RecoveredCacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.src = self.base/'source.py'; self.src.write_text('print(2+3)\n')
        self.transport = FakeTransport()
        self.adapter = KaggleAdapter(self.transport, self.base/'state')
        self.adapter.submit(request_id='original-1', source=self.src, timeout=120)
        self.transport.state = 'COMPLETE'
        self.cache = self.base/'external'; self.cache.mkdir(mode=0o700)
        self.payloads = {'nested/result.bin': b'\x00A\xffB\n', 'empty': b''}
        self.prepare(self.payloads)

    def prepare(self, payloads):
        for name, value in payloads.items():
            p=self.cache/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(value)
        manifest={'schema':'hepta-artifact-manifest-v1','request_id':'original-1',
                  'files':[{'path':k,'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for k,v in payloads.items()]}
        m=json.dumps(manifest).encode();self.pin=hashlib.sha256(m).hexdigest()
        self.transport.payloads={**payloads,'hepta-manifest.json':m}
        self.total=sum(map(len,self.transport.payloads.values()))

    def run_import(self, **kw):
        args={'manifest_name':'hepta-manifest.json','cache_root':self.cache,'cache_manifest_sha256':self.pin,'max_bytes':self.total}
        args.update(kw)
        return self.adapter.artifacts('original-1',**args)

    def reject(self, code, **kw):
        with self.assertRaises(AdapterError) as ctx:self.run_import(**kw)
        self.assertEqual(ctx.exception.code,code)
        self.assertFalse((self.adapter.ledger.directory('original-1')/'artifacts/v1').exists())
        self.assertNotIn('artifacts',self.adapter.ledger.load('original-1'))
        self.assertEqual(self.transport.count('submit'),1)

    def test_complete_import_downloads_only_manifest_then_existing_collect_reuses(self):
        before=copy.deepcopy(self.adapter.ledger.load('original-1'))
        receipt=self.run_import()
        self.assertEqual(self.transport.downloads,['hepta-manifest.json'])
        self.assertEqual(receipt['verification_policy'],'fresh-manifest-and-recovered-cache-v1')
        self.assertEqual(receipt['recovered_cache']['manifest_sha256'],self.pin)
        self.assertEqual(receipt['recovered_cache']['payload_files'],2)
        self.assertFalse(receipt['recovered_cache']['cloud_mutation_performed'])
        actual={x['path']:x for x in receipt['files']}
        for name,value in self.payloads.items():
            self.assertEqual((Path(receipt['directory'])/name).read_bytes(),value)
            self.assertEqual(actual[name]['retrieval'],'verified_local_cache')
            self.assertIsNone(actual[name]['http_content_length'])
            self.assertFalse(actual[name]['http_content_length_verified'])
        count=len(self.transport.calls)
        repeated=self.adapter.artifacts('original-1',manifest_name='hepta-manifest.json',max_bytes=self.total)
        self.assertTrue(repeated['reused']);self.assertEqual(len(self.transport.calls),count)
        after=self.adapter.ledger.load('original-1')
        for key in ('request_id','input_digest','account','intent','submission_state','notebook_ref','notebook_version','kernel_id'):
            self.assertEqual(before[key],after[key])
        self.assertEqual(self.transport.count('submit'),1)
        for action,values,mutation in self.transport.calls:
            if action in ('get','status','files','output'):
                self.assertEqual(values['version_label'],'v1');self.assertFalse(mutation)

    def test_real_create_only_subclass_inherits_exact_import_implementation(self):
        self.assertIs(CreateOnlyKaggleAdapter.artifacts,KaggleAdapter.artifacts)
        self.adapter=CreateOnlyKaggleAdapter(self.transport,self.base/'state')
        self.assertEqual(self.run_import()['notebook_version'],1)
        self.assertEqual(self.transport.count('submit'),1)

    def test_wrong_remote_manifest_pin_never_reads_cache(self):
        with patch('kaggle_jobs.copy_recovered_payload') as copied:
            self.reject('CACHE_MANIFEST_PIN_MISMATCH',cache_manifest_sha256='0'*64);copied.assert_not_called()

    def test_cache_manifest_is_not_authority(self):
        (self.cache/'hepta-manifest.json').write_bytes(b'{"fake":true}')
        self.assertEqual(self.run_import()['recovered_cache']['manifest_sha256'],self.pin)

    def test_cache_requires_manifest_and_prior_pin(self):
        self.reject('CACHE_MANIFEST_REQUIRED',manifest_name=None)
        self.reject('CACHE_MANIFEST_REQUIRED',cache_manifest_sha256=None)
        self.reject('CACHE_MANIFEST_REQUIRED',cache_manifest_sha256='malformed')
        self.reject('CACHE_ROOT_REQUIRED',cache_root=None)

    def test_fresh_http_manifest_requires_length(self):
        self.transport.http_lengths['hepta-manifest.json']=None
        self.reject('HTTP_CONTENT_LENGTH_REQUIRED')

    def test_fresh_http_manifest_size_mismatch_rejects(self):
        self.transport.http_lengths['hepta-manifest.json']=1
        self.reject('ARTIFACT_LENGTH')

    def test_existing_unacknowledged_or_kernel_unbound_state_cannot_be_fixed_by_cache(self):
        rec=self.adapter.ledger.load('original-1')
        rec['submission_state']='UNKNOWN';self.adapter.ledger.save(rec)
        self.reject('CACHE_ORIGINAL_EXECUTION_UNBOUND')
        rec['submission_state']='ACCEPTED';rec['kernel_id']=None;self.adapter.ledger.save(rec)
        self.reject('CACHE_ORIGINAL_EXECUTION_UNBOUND')

    def test_actual_remote_completion_required_despite_local_complete(self):
        rec=self.adapter.ledger.load('original-1');rec['remote_state']='COMPLETE';self.adapter.ledger.save(rec)
        self.transport.state='RUNNING'
        self.reject('REMOTE_NOT_COMPLETE')
        self.assertEqual(self.transport.downloads,[])

    def test_changed_source_rejects(self):
        self.transport.source_override='print(9)\n';self.reject('SOURCE_IDENTITY_MISMATCH')

    def test_changed_account_rejects(self):
        self.transport.username='someone_else';self.reject('ACCOUNT_MISMATCH')

    def test_changed_kernel_id_rejects(self):
        self.transport.kernel_id=10;self.reject('NOTEBOOK_IDENTITY_MISMATCH')

    def test_wrong_manifest_request_rejects_even_with_matching_prior_hash(self):
        m=json.loads(self.transport.payloads['hepta-manifest.json']);m['request_id']='other'
        raw=json.dumps(m).encode();self.transport.payloads['hepta-manifest.json']=raw;self.pin=hashlib.sha256(raw).hexdigest();self.total=sum(map(len,self.transport.payloads.values()))
        self.reject('REMOTE_MANIFEST_IDENTITY')

    def test_manifest_must_cover_full_fixed_version_listing(self):
        self.transport.payloads['not-in-manifest']=b'x';self.total+=1
        self.reject('REMOTE_MANIFEST_COVERAGE')

    def test_budget_checked_before_payload_copy(self):
        with patch('kaggle_jobs.copy_recovered_payload') as copied:
            self.reject('ARTIFACT_BUDGET',max_bytes=self.total-1);copied.assert_not_called()

    def test_corrupt_payload_rejects_and_retains_failure_event(self):
        (self.cache/'nested/result.bin').write_bytes(b'\x00X\xffB\n')
        self.reject('CACHE_PAYLOAD_CHANGED_OR_HASH')
        self.assertEqual(self.adapter.ledger.load('original-1')['events'][-1]['kind'],'artifact_download_failed')

    def test_missing_or_short_payload_rejects(self):
        (self.cache/'nested/result.bin').unlink();self.reject('UNSAFE_CACHE_PAYLOAD')
        (self.cache/'nested/result.bin').write_bytes(b'x');self.reject('CACHE_PAYLOAD_SIZE')

    def test_root_and_nested_symlinks_are_rejected(self):
        link=self.base/'link';link.symlink_to(self.cache,target_is_directory=True);self.reject('UNSAFE_CACHE_ROOT',cache_root=link)
        nested=self.cache/'nested';nested.rename(self.base/'moved');nested.symlink_to(self.base/'moved',target_is_directory=True)
        self.reject('UNSAFE_CACHE_PAYLOAD')

    def test_leaf_symlink_hardlink_and_fifo_are_rejected(self):
        p=self.cache/'nested/result.bin';p.unlink();p.symlink_to(self.src);self.reject('UNSAFE_CACHE_PAYLOAD')
        p.unlink();os.link(self.src,p);self.reject('UNSAFE_CACHE_PAYLOAD')
        p.unlink();os.mkfifo(p);self.reject('UNSAFE_CACHE_PAYLOAD')

    def test_group_writable_root_and_adapter_state_cache_rejected(self):
        self.cache.chmod(0o770);self.reject('UNSAFE_CACHE_ROOT');self.cache.chmod(0o700)
        self.reject('INVALID_CACHE_ROOT',cache_root=self.adapter.ledger.root)
        self.reject('INVALID_CACHE_ROOT',cache_root=Path('relative'))

    def test_provider_size_conflicts_do_not_invent_http_lengths(self):
        self.transport.provider_sizes={name:999 for name in self.transport.payloads}
        receipt=self.run_import();self.assertEqual(len(receipt['warnings']),3)
        for x in receipt['files']:
            if x['path']!='hepta-manifest.json':self.assertIsNone(x['http_content_length'])
        again=self.adapter.artifacts('original-1',manifest_name='hepta-manifest.json',max_bytes=self.total)
        self.assertTrue(again['reused'])

    def test_reuse_rejects_silent_policy_downgrade_or_requested_pin_mismatch(self):
        self.run_import()
        with self.assertRaises(AdapterError) as e:self.adapter.artifacts('original-1',max_bytes=self.total)
        self.assertEqual(e.exception.code,'CACHE_MANIFEST_REQUIRED')
        with self.assertRaises(AdapterError) as e:self.run_import(cache_manifest_sha256='0'*64)
        self.assertEqual(e.exception.code,'CACHE_MANIFEST_PIN_MISMATCH')

    def test_reuse_rejects_corrupt_payload_and_false_provenance(self):
        receipt=self.run_import();rec=self.adapter.ledger.load('original-1')
        rec['artifacts']['files'][0]['retrieval']='fresh_http_manifest'
        rec['artifacts']['files_manifest_sha256']=digest(rec['artifacts']['files']);self.adapter.ledger.save(rec)
        # Item 0 is manifest. Damage a payload explicitly, preserving only generic list digest.
        rec=self.adapter.ledger.load('original-1')
        next(x for x in rec['artifacts']['files'] if x['path']=='empty')['http_content_length_verified']=True
        rec['artifacts']['files_manifest_sha256']=digest(rec['artifacts']['files']);self.adapter.ledger.save(rec)
        with self.assertRaises(AdapterError) as e:self.adapter.artifacts('original-1',manifest_name='hepta-manifest.json')
        self.assertEqual(e.exception.code,'CACHE_RECEIPT_PROVENANCE')

    def test_original_publication_crash_recovery_works_without_download(self):
        receipt=self.run_import();rec=self.adapter.ledger.load('original-1');rec.pop('artifacts');self.adapter.ledger.save(rec)
        old=len(self.transport.downloads)
        out=self.adapter.artifacts('original-1',manifest_name='hepta-manifest.json',max_bytes=self.total)
        self.assertTrue(out['recovered_local_publish']);self.assertEqual(len(self.transport.downloads),old)

    def test_external_transport_failure_is_not_mislabelled_as_bad_cache_root(self):
        original=self.transport.download
        def fail(*a,**kw):raise OSError('retained simulated transport failure')
        self.transport.download=fail
        with self.assertRaisesRegex(OSError,'retained simulated'):self.run_import()
        self.assertEqual(self.adapter.ledger.load('original-1')['events'][-1]['kind'],'artifact_download_failed')
        self.transport.download=original

    def test_2336_payload_contract_uses_one_fresh_download_and_exact_full_reuse(self):
        payloads={f'recovered/{i:04d}.bin':bytes([i%251])*((i%13)+1) for i in range(2336)}
        self.prepare(payloads)
        out=self.run_import();self.assertEqual(len(out['files']),2337)
        self.assertEqual(out['recovered_cache']['payload_files'],2336)
        self.assertEqual(self.transport.downloads,['hepta-manifest.json'])
        again=self.adapter.artifacts('original-1',manifest_name='hepta-manifest.json',max_bytes=self.total)
        self.assertTrue(again['reused']);self.assertEqual(out['files_manifest_sha256'],again['files_manifest_sha256'])

    def test_deployed_basename_catalog_ambiguity_keeps_exact_output_authority(self):
        self.prepare({'left/result.bin':b'L','right/result.bin':b'R'})
        self.adapter=CreateOnlyKaggleAdapter(self.transport,self.base/'state')
        original=self.transport.call
        def display(action, values, **kw):
            if action=='files':
                self.transport.calls.append((action,dict(values),False))
                return {'files':[{'name':'result.bin','size':999},{'name':'result.bin','size':888},
                                 {'name':'hepta-manifest.json','size':777}]}
            return original(action,values,**kw)
        self.transport.call=display
        out=self.run_import()
        codes={x['code'] for x in out['warnings']}
        self.assertIn('PROVIDER_AMBIGUOUS_DISPLAY_BASENAMES',codes)
        self.assertIn('PROVIDER_OUTPUT_CATALOG_CONFLICT',codes)
        self.assertEqual({x['path'] for x in out['files']},{'left/result.bin','right/result.bin','hepta-manifest.json'})
        self.assertEqual(self.transport.downloads,['hepta-manifest.json'])

    def test_cli_routes_original_identity_and_cache_options_through_actual_subclass(self):
        import contextlib,io
        from deployed_cli_fixture import deployed_cli as hepta_kaggle
        captured=io.StringIO()
        argv=['--state-dir',str(self.base/'state'),'artifacts','--request-id','original-1',
              '--max-bytes',str(self.total),'--manifest-name','hepta-manifest.json',
              '--cache-root',str(self.cache),'--cache-manifest-sha256',self.pin]
        with patch.object(hepta_kaggle,'KaggleTransport',return_value=self.transport), contextlib.redirect_stdout(captured):
            rc=hepta_kaggle.main(argv)
        data=json.loads(captured.getvalue())
        self.assertEqual(rc,0);self.assertTrue(data['ok'])
        self.assertEqual(data['result']['request_id'],'original-1')
        self.assertEqual(data['result']['verification_policy'],'fresh-manifest-and-recovered-cache-v1')
        self.assertEqual(self.transport.count('submit'),1)

    def test_context_manager_preserves_runtime_error_and_never_publishes_partial_cache(self):
        import kaggle_jobs
        original=kaggle_jobs.copy_recovered_payload
        def fail(*a,**kw):
            if a[1]=='nested/result.bin':raise RuntimeError('simulated retained interruption after first empty payload')
            return original(*a,**kw)
        with patch('kaggle_jobs.copy_recovered_payload',side_effect=fail):
            with self.assertRaisesRegex(RuntimeError,'simulated retained interruption'):self.run_import()
        self.assertFalse((self.adapter.ledger.directory('original-1')/'artifacts/v1').exists())
        rec=self.adapter.ledger.load('original-1')
        self.assertNotIn('artifacts',rec);self.assertEqual(rec['events'][-1]['kind'],'artifact_download_failed')
        self.assertEqual(list(self.adapter.ledger.directory('original-1').glob('.download-*')),[])



if __name__=='__main__':unittest.main()
