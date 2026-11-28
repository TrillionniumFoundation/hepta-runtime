"""Refuse incomplete retained OS-scope receipts without executing an owner."""
from copy import deepcopy
from pathlib import Path
import gzip
import hashlib
import json
import os
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"scripts"))
import hia_native_scope_os_qualification as qualification
sys.path.insert(0,str(ROOT/"tests/hia_native"))
import scope_os_supervisor as supervisor

COUNTS={"accepted_reference_reports":0,"mutation_refusals":0,"classifier_admissions":0,
        "classifier_refusals":0,"native_calls_added":0,"original_calls_added":0}


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=ROOT/"tests/hia_native/scope_os_receipt_fixture.json.gz"
        cls.data=json.loads(gzip.decompress(cls.fixture.read_bytes()))
        assert cls.data["schema"]=="hepta.runtime.scope-os-retained-receipts.v2"
        cls.native,cls.original=cls.data["native"],cls.data["original"]
        cls.vdso=cls.data["original_vdso"]
        cls.vdso195=cls.data["original_vdso_195"]
        cls.native_ai395=cls.data["native_ai395"]

    def validate(self,value,original=True,baseline=None):
        if baseline is None:baseline=self.original if original else self.native
        return qualification.kernel_evidence(ROOT,value,baseline["artifact"],
                   original_binary_sha256=baseline["original_executable_sha256"] if original else None)

    def refused(self,mutate,original=True):
        value=deepcopy(self.original if original else self.native)
        mutate(value)
        with self.assertRaises(ValueError): self.validate(value,original)
        COUNTS["mutation_refusals"]+=1

    def test_complete_retained_native_and_original_reports(self):
        for original,baseline in ((False,self.native),(False,self.native_ai395),
                                  (True,self.original),(True,self.vdso195),(True,self.vdso)):
            value=self.validate(baseline,original,baseline)
            self.assertEqual(value["status"],"PASS")
            self.assertEqual(value["original_owner_calls"],220 if original else 0)
            self.assertEqual(len(value["process_domains"]),31 if original else 0)
            COUNTS["accepted_reference_reports"]+=1

    def test_observed_profiles_and_mixed_run_rejection(self):
        def auxiliary(value):return value["cases"][0]["original"]["trace"]["original_auxiliary_entropy"]
        def profile(value):return tuple(auxiliary(value)[0][key] for key in ("requested","flags"))
        self.assertEqual(profile(self.original),(16,4))
        self.assertEqual(profile(self.vdso),(32,0))
        self.assertEqual(profile(self.vdso195),(32,0))
        self.assertEqual(self.original["original_executable_sha256"],self.vdso195["original_executable_sha256"])
        self.refused(lambda value:auxiliary(value).append(deepcopy(auxiliary(value)[0])))
        self.refused(lambda value:auxiliary(value)[0].__setitem__("requested",True))
        self.refused(lambda value:auxiliary(value)[0].__setitem__("flags",False))
        self.refused(lambda value:auxiliary(value)[0].update(requested=16,flags=0))
        self.refused(lambda value:auxiliary(value)[0].update(requested=32,flags=4))
        self.refused(lambda value:auxiliary(value)[0].update(requested=32,flags=0))
        self.refused(lambda value:auxiliary(value)[0].__setitem__("flags",3))
        self.refused(lambda value:value["cases"][0].__setitem__("original",deepcopy(self.vdso["cases"][0]["original"])))

    def test_live_classifier_separates_fault_and_seed_domains(self):
        direct={"module_kind":"libc","symbol":"getrandom"}
        vdso={"module_kind":"linux-vdso","symbol":"__vdso_getrandom"}
        system={"module_kind":"libc","symbol":"syscall"}
        self.assertEqual(supervisor.original_rng_domain(None,8,1),"process_runtime_startup")
        COUNTS["classifier_admissions"]+=1
        for site in (direct,vdso):
            for size,flags in ((16,4),(32,0)):
                self.assertEqual(supervisor.original_rng_domain(site,size,flags),"original_standard_library")
                COUNTS["classifier_admissions"]+=1
        for size in (0,12,32,128):
            self.assertEqual(supervisor.original_rng_domain(system,size,0),"system_entropy")
            COUNTS["classifier_admissions"]+=1
        bad=[(direct,12,0,False),(direct,0,0,False),(direct,16,0,False),(direct,32,4,False),
             (direct,129,0,False),(direct,-1,0,False),(direct,True,0,False),(direct,32,False,False),
             (direct,32,1,False),(direct,32,2,False),(direct,32,8,False),(direct,"32",0,False),
             (system,16,4,False),(system,128,4,False),
             ({"module_kind":"libc","symbol":"unknown"},32,0,False),
             ({"module_kind":"unidentified","symbol":"getrandom"},32,0,False),
             ({"module_kind":"libc","symbol":"__vdso_getrandom"},32,0,False),
             ({"module_kind":"linux-vdso","symbol":"getrandom"},32,0,False),
             (direct,32,0,True),(vdso,16,4,True)]
        for site,size,flags,seen in bad:
            with self.assertRaises(AssertionError):supervisor.original_rng_domain(site,size,flags,seed_seen=seen)
            COUNTS["classifier_refusals"]+=1
        for size,flags,state in ((8,1,{"input_started":True}),(8,1,{"startup_seen":True}),
                                 (8,1,{"prior_rng_calls":1}),(16,1,{}),(8,0,{})):
            with self.assertRaises(AssertionError):supervisor.original_rng_domain(None,size,flags,**state)
            COUNTS["classifier_refusals"]+=1

    def test_complete_startup_and_getrandom_notification_accounting(self):
        def trace(value):return value["cases"][0]["original"]["trace"]
        self.refused(lambda value:trace(value)["original_startup_entropy"].clear())
        self.refused(lambda value:trace(value)["original_startup_entropy"].append(deepcopy(trace(value)["original_startup_entropy"][0])))
        for key,bad in (("before_input",False),("kind","standard_library_hashset_seed"),
                        ("requested",16),("flags",0),("getrandom_index",1)):
            self.refused(lambda value,k=key,b=bad:trace(value)["original_startup_entropy"][0].__setitem__(k,b))
        self.refused(lambda value:trace(value).__setitem__("original_getrandom_syscalls",trace(value)["original_getrandom_syscalls"]-1))

    def test_missing_or_misclassified_auxiliary_calls(self):
        def auxiliary(value): return value["cases"][0]["original"]["trace"]["original_auxiliary_entropy"]
        self.refused(lambda value:auxiliary(value).clear())
        for key,bad in (("requested",12),("flags",1),("completion","injected_error")):
            self.refused(lambda value,k=key,b=bad:auxiliary(value)[0].__setitem__(k,b))
        for key,bad in (("library_sha256",""),("module_kind","unidentified"),("symbol","syscall"),("instruction_offset",0)):
            self.refused(lambda value,k=key,b=bad:auxiliary(value)[0]["callsite"].__setitem__(k,b))

    def test_complete_domain_order_and_module_identity(self):
        def trace(value): return value["cases"][0]["original"]["trace"]
        self.refused(lambda value:trace(value)["entropy_event_order"].pop(0))
        self.refused(lambda value:trace(value)["entropy_event_order"].append(trace(value)["entropy_event_order"].pop(0)))
        self.refused(lambda value:trace(value)["original_system_rng_callsites"].pop())
        self.refused(lambda value:trace(value)["original_system_rng_callsites"][0].__setitem__("library_sha256","0"*64))
        self.refused(lambda value:trace(value)["events"][1].__setitem__("requested",11))

    def test_complete_native_cleanup_and_cache_lifetime(self):
        def trace(value): return value["cases"][0]["native"]["trace"]
        for key,bad in (("private_workspaces_zero",False),("transport_output_zero",False),
                        ("private_entropy_descriptors_retired",False),("inspected_bytes",40),("exit_code",2)):
            self.refused(lambda value,k=key,b=bad:trace(value)["native_cleanup"].__setitem__(k,b))
        self.refused(lambda value:trace(value)["native_idle_snapshots"][-1].__setitem__("entropy_sequence",0))
        self.refused(lambda value:trace(value)["native_idle_snapshots"][-1].__setitem__("private_keys_zero",False))
        self.refused(lambda value:value["cases"][34]["native"]["trace"]["native_idle_snapshots"][-1].__setitem__("entropy_cached_fd",0))

    def test_source_status_and_claims(self):
        self.refused(lambda value:value.__setitem__("status","PENDING"))
        self.refused(lambda value:value.__setitem__("source_unchanged",False))
        self.refused(lambda value:value["source_sha256"].__setitem__("scope_os_supervisor.py","0"*64))
        self.refused(lambda value:value.__setitem__("original_source_sha256","0"*64))
        self.refused(lambda value:value.__setitem__("normal_random_bytes_equality_claimed",True))
        self.refused(lambda value:value.__setitem__("production_activated",True))

    def test_actual_owner_and_declared_response_domains(self):
        self.refused(lambda value:value["cases"].pop())
        self.refused(lambda value:value["cases"][0].__setitem__("original",None))
        self.refused(lambda value:value["cases"][0]["original"]["original_owner"].__setitem__("original_seals",2))
        self.refused(lambda value:value["cases"][0]["original"]["rows"][2].__setitem__("output_sha256","0"*64))
        self.refused(lambda value:value["counts"].__setitem__("native_processes",True))
        self.refused(lambda value:value["cases"][18].__setitem__("original",deepcopy(self.original["cases"][0]["original"])))


if __name__=="__main__":
    result=unittest.main(exit=False,verbosity=2).result
    expected={"accepted_reference_reports":5,"mutation_refusals":49,"classifier_admissions":9,
              "classifier_refusals":25,"native_calls_added":0,"original_calls_added":0}
    complete=(result.wasSuccessful() and result.testsRun==9 and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses and COUNTS==expected)
    report={"schema":"hepta.runtime.scope-os-evidence-test.v1","status":"PASS" if complete else "FAIL",
            "tests_run":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),"skipped":len(result.skipped),
            "counts":COUNTS,"expected_counts":expected,
            "test_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "helper_sha256":hashlib.sha256((ROOT/"scripts/hia_native_scope_os_qualification.py").read_bytes()).hexdigest(),
            "fixture_sha256":hashlib.sha256(EvidenceTests.fixture.read_bytes()).hexdigest()}
    target=os.environ.get("HIA_SCOPE_OS_EVIDENCE_RESULT")
    if target:
        with Path(target).open("x") as stream: stream.write(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report,sort_keys=True))
    raise SystemExit(0 if complete else 1)
