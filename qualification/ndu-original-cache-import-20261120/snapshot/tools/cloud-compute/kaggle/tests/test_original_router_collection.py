"""Use the exact deployed router body and actual adapter CLI with only transport mocked.

All local ledgers are new temporary fixtures. No host credentials, production
ledger, provider operation or scientific observation is used by these tests.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from kaggle_jobs import KaggleAdapter
from kaggle_create_only import CreateOnlyKaggleAdapter
from test_jobs import FakeTransport
import hepta_kaggle

ROUTER_SOURCE=Path(__file__).resolve().parents[4]/'qualification/hepta_compute_base.py'
ROUTER_SHA='5b55efba3496b74a00b525b656e41617cc8157b287a69e21ea7896b1236fcb8d'
assert hashlib.sha256(ROUTER_SOURCE.read_bytes()).hexdigest()==ROUTER_SHA
spec=importlib.util.spec_from_file_location('frozen_deployed_router',ROUTER_SOURCE)
router_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(router_module)

class OriginalRouterCollectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.transport=FakeTransport();self.calls=[]
        self.adapter_state=self.base/'adapter'
        owner=self
        class OriginalCliLauncher:
            def call(self,provider,account,args,timeout=90):
                owner.calls.append((provider,account,list(args),timeout))
                assert provider=='kaggle' and account=='qiqian' and args[0]=='batch'
                capture=io.StringIO()
                with patch('hepta_kaggle.KaggleTransport',return_value=owner.transport),contextlib.redirect_stdout(capture):
                    rc=hepta_kaggle.main(['--state-dir',str(owner.adapter_state),*args[1:]])
                out=json.loads(capture.getvalue())
                if not out.get('ok'):
                    raise router_module.RouterError(out['error']['code'])
                assert rc==0
                return out['result']
        self.router=router_module.Router(home=self.base/'home',state=self.base/'router',launcher=OriginalCliLauncher())
        self.rid='original-software-cache-1'
        self.provider_id='hc-'+router_module.digest(self.rid.encode())[:40]
        d=self.router.store.job_dir(self.rid);source=d/'source.py';source.write_bytes(b'print("original body")\n')
        intent={'source_sha256':router_module.digest(source.read_bytes()),'timeout':120,'accelerator':'cpu',
                'requested_provider':'kaggle','requested_account':'qiqian','artifacts':['mastery_complete.tar.xz','mastery_summary.json'],
                'kaggle_internet':False,'kaggle_private':True}
        self.record={'schema':'hepta-compute-job-v1','router_version':'0.1.3-integrity+adoption-v1',
                     'request_id':self.rid,'provider_request_id':self.provider_id,'provision_key':self.provider_id,
                     'digest':router_module.digest(router_module.canonical(intent)),'provider':'kaggle','account':'qiqian',
                     'account_identity_sha256':router_module.account_identity('kaggle',self.transport.account()),
                     'intent':intent,'source':str(source),'state':'REMOTE_TERMINAL','lease_until':time.time()+900,
                     'effects':{'submit':{'status':'confirmed'}},'receipts':{},
                     'events':[{'at':'fixture-original','event':'previous_download_failure_retained'}]}
        router_module.add_kaggle_artifact_envelope(self.record,d)
        # Fixture only: create an acknowledged original record through unchanged base submit.
        a=KaggleAdapter(self.transport,self.adapter_state)
        a.submit(request_id=self.provider_id,source=Path(self.record['execution_source']['path']),timeout=120)
        self.adapter=CreateOnlyKaggleAdapter(self.transport,self.adapter_state)
        self.transport.state='COMPLETE';self.transport.log='original complete\n'
        payloads={'mastery_complete.tar.xz':b'original archive bytes','mastery_summary.json':b'{"original":true}\n','nested/record.json':b'{"sample":1}\n'}
        manifest={'schema':'hepta-artifact-manifest-v1','request_id':self.provider_id,
                  'files':[{'path':k,'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for k,v in payloads.items()]}
        self.manifest=json.dumps(manifest).encode();self.pin=hashlib.sha256(self.manifest).hexdigest()
        self.transport.payloads={**payloads,router_module.KAGGLE_MANIFEST_NAME:self.manifest}
        self.total=sum(map(len,self.transport.payloads.values()))
        self.cache=self.base/'external';self.cache.mkdir(mode=0o700)
        for k,v in payloads.items():p=self.cache/k;p.parent.mkdir(exist_ok=True);p.write_bytes(v)
        with self.router.store.connection() as db:
            r=self.record;db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?)',(r['request_id'],r['digest'],r['provider'],r['account'],r['state'],r['lease_until'],router_module.canonical(r).decode()))
        self.import_receipt=self.adapter.artifacts(self.provider_id,max_bytes=self.total,
            manifest_name=router_module.KAGGLE_MANIFEST_NAME,cache_root=self.cache,cache_manifest_sha256=self.pin)

    def test_original_collect_actual_cli_rechecks_published_bytes_and_releases_only_original_reservation(self):
        original=self.router.store.get(self.rid)
        self.assertEqual(len(self.router.store.reservations()),1)
        result=self.router.collect(self.rid,max_bytes=self.total)
        self.assertEqual(result['state'],'COLLECTED');self.assertEqual(result['lease_until'],0)
        self.assertEqual(self.router.store.reservations(),[])
        self.assertEqual(result['events'][0],original['events'][0])
        for key in ('request_id','provider_request_id','provider','account','digest','intent','execution_source'):
            self.assertEqual(result[key],original[key])
        artifact_call=next(x for x in self.calls if x[2][1]=='artifacts')
        self.assertEqual(artifact_call[2],['batch','artifacts','--request-id',self.provider_id,'--max-bytes',str(self.total),'--manifest-name','hepta-execution-manifest.json'])
        self.assertEqual(self.transport.downloads,['hepta-execution-manifest.json'])
        self.assertEqual(self.transport.count('submit'),1)
        self.assertFalse(any(x[2][1] in ('submit','cancel','release') for x in self.calls))
        self.assertEqual(len(result['outputs']['files']),4)
        for f in result['outputs']['files']:
            body=Path(f['path']).read_bytes();self.assertEqual(len(body),f['bytes']);self.assertEqual(hashlib.sha256(body).hexdigest(),f['sha256'])
        before=len(self.calls)
        self.assertEqual(self.router.collect(self.rid,max_bytes=self.total)['state'],'COLLECTED')
        self.assertEqual(len(self.calls),before)

    def test_remote_nonterminal_does_not_finalize_despite_published_cache(self):
        self.transport.state='RUNNING'
        with self.assertRaises(router_module.RouterError) as ctx:self.router.collect(self.rid,max_bytes=self.total)
        self.assertEqual(ctx.exception.code,'REMOTE_COMPLETION_UNCONFIRMED')
        self.assertEqual(len(self.router.store.reservations()),1)
        self.assertNotEqual(self.router.store.get(self.rid)['state'],'COLLECTED')

    def test_corrupt_retained_bytes_do_not_finalize(self):
        (Path(self.import_receipt['directory'])/'mastery_summary.json').write_bytes(b'changed')
        with self.assertRaises(router_module.RouterError) as ctx:self.router.collect(self.rid,max_bytes=self.total)
        self.assertEqual(ctx.exception.code,'LOCAL_ARTIFACT_CHANGED')
        self.assertEqual(len(self.router.store.reservations()),1)
        self.assertEqual(self.router.store.get(self.rid)['state'],'REMOTE_TERMINAL')

    def test_original_wrapper_binding_is_still_enforced(self):
        Path(self.record['source']).write_bytes(b'print("changed")\n')
        with self.assertRaises(router_module.RouterError) as ctx:self.router.collect(self.rid,max_bytes=self.total)
        self.assertEqual(ctx.exception.code,'EXECUTION_SOURCE_CHANGED')
        self.assertEqual(len(self.router.store.reservations()),1)
        self.assertEqual(self.router.store.get(self.rid)['state'],'REMOTE_TERMINAL')

if __name__=='__main__':unittest.main()
