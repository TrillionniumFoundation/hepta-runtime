"""Real-file synchronous owner parity; async worker ownership remains separate."""
from pathlib import Path
import errno
import fcntl
import gzip
import hashlib
import json
import os
import select
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from effect_fence_test_support import Fixture, Session, COUNTS, ROWS, executable, sha


class OwnerTests(unittest.TestCase):
    def admit(self, fixture, case="ordinary", **kw):
        p = fixture.session(case, **kw)
        self.assertEqual(p.call(1), (0, 0, fixture.epoch, int(fixture.role == "v11")))
        return p

    def test_01_configuration_and_legacy_mode(self):
        cases = [
            ({"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "0"}, 1),
            ({"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": ""}, 1),
            ({"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "true"}, 1),
            ({"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": b"\xff"}, 1),
            ({"HEPTA_EFFECT_OWNER_FENCE_DIR": None}, 2),
            ({"HEPTA_EFFECT_OWNER_SELF": None}, 2),
            ({"HEPTA_EFFECT_OWNER_SELF": b"\xff"}, 3),
            ({"HEPTA_EFFECT_OWNER_SELF": "v10"}, 4),
            ({"HEPTA_EFFECT_OWNER_FENCE_DIR": "relative"}, 5),
            ({"HEPTA_EFFECT_OWNER_FENCE_DIR": ""}, 5),
        ]
        for index, (env, code) in enumerate(cases):
            with self.subTest(index=index), Fixture() as f:
                p = f.session("config-" + str(index), config=env)
                self.assertEqual(p.call(1)[0], code)
        with Fixture() as f:
            p = self.admit(f, "config-required", config={"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "1"})
            self.assertEqual(p.call(4), (0, 0, 0, 0))
        for required in (None, "1"):
            with Fixture() as f:
                env = {"HEPTA_EFFECT_OWNER_FENCE_DIR": None, "HEPTA_EFFECT_OWNER_SELF": None,
                       "HEPTA_EFFECT_OWNER_FENCE_REQUIRED": required}
                p = f.session("legacy-" + str(required), config=env, state="relative")
                self.assertEqual(p.call(1)[0], 0 if required is None else 2)
                if required is None:
                    self.assertEqual(p.call(2, "", None), (0, 0, 0, 0))
                    self.assertEqual(p.call(3, "/invalid", ""), (0, 0, 0, 0))
                    self.assertEqual(p.call(4), (0, 0, 0, 0))
        with Fixture() as f:
            p = f.session("relative-state", state="relative")
            self.assertEqual(p.call(1)[0], 4)

    def test_02_private_roots_and_authority_inodes(self):
        def remove_lock(f):
            (f.authority / ".owner.lock").unlink()
        def lock_link(f):
            os.link(f.authority / ".owner.lock", f.directory / "linked-lock")
        def owner_link(f):
            os.link(f.authority / ".owner.json", f.directory / "linked-owner")
        def owner_symlink(f):
            p = f.authority / ".owner.json";p.rename(f.directory / "record")
            p.symlink_to(f.directory / "record")
        def owner_fifo(f):
            p = f.authority / ".owner.json";p.unlink();os.mkfifo(p, 0o600)
        cases = [
            (lambda f: f.authority.chmod(0o750), 10),
            (lambda f: f.state.chmod(0o755), 10),
            (lambda f: f.state.rmdir(), 8),
            (remove_lock, 11), (lock_link, 12), (owner_link, 12), (owner_symlink, 11),
            (owner_fifo, 12),
            (lambda f: (f.authority / ".owner.lock").chmod(0o640), 12),
            (lambda f: (f.authority / ".owner.json").chmod(0o640), 12),
            (lambda f: f.write(f.authority / ".owner.json", b""), 14),
            (lambda f: f.write(f.authority / ".owner.json", b" " * 4097), 14),
            (lambda f: f.write(f.authority / ".owner.json", b"{}"), 17),
        ]
        for index, (setup, code) in enumerate(cases):
            with self.subTest(index=index), Fixture() as f:
                setup(f);p = f.session("private-" + str(index))
                self.assertEqual(p.call(1)[0], code)
        with Fixture() as f:
            f.authority.chmod(0o1700)
            (f.authority / ".owner.lock").chmod(0o4600)
            (f.authority / ".owner.json").chmod(0o2600)
            p = self.admit(f, "special-permission-bits-allowed")
            self.assertEqual(p.call(4)[0], 0)
        with Fixture() as f:
            alias = f.directory / "alias";alias.symlink_to(f.authority, target_is_directory=True)
            p = f.session("symlinked-authority-ancestor", config={"HEPTA_EFFECT_OWNER_FENCE_DIR": str(alias)})
            self.assertEqual(p.call(1)[:2], (8, errno.ENOTDIR))
        with Fixture() as f:
            p = self.admit(f, "normalized-state", state=str(f.state) + "///./",
                config={"HEPTA_EFFECT_OWNER_FENCE_DIR": str(f.authority) + "///./"})
            self.assertEqual(p.call(4)[0], 0)
        with Fixture() as f:
            p = f.session("parent-component", config={"HEPTA_EFFECT_OWNER_FENCE_DIR": str(f.authority) + "/.."})
            self.assertEqual(p.call(1)[0], 6)

    def test_03_typed_owner_record_and_order(self):
        changes = [({"schema":"other"},18), ({"epoch":0},18), ({"epoch":-1},17),
            ({"epoch":1.0},17), ({"epoch":True},17), ({"epoch":1<<64},17),
            ({"owner":"other"},18), ({"phase":"other"},18), ({"phase":"frozen"},19),
            ({"state_root":"relative"},18), ({"unexpected":True},17),
            ({"owner":None},17), ({"predecessor_state_root":""},22)]
        for index, (values, code) in enumerate(changes):
            with self.subTest(index=index), Fixture() as f:
                f.record(**values);p=f.session("typed-owner-"+str(index))
                self.assertEqual(p.call(1)[0],code)
        for array in (True, False):
            with Fixture(epoch=(1<<64)-1) as f:
                value=f.record()
                if array:
                    raw=json.dumps([value[k] for k in ("schema","owner","epoch","phase","state_root")]).encode()
                else:
                    raw=json.dumps(value).encode()
                f.write(f.authority/".owner.json",raw+b" "*(4096-len(raw)))
                p=self.admit(f,"owner-maximum-"+str(array));self.assertEqual(p.call(4)[0],0)
        for raw_suffix in (b',"owner":"v4"}', b',"predecessor_state_root":null,"predecessor_state_root":null}'):
            with Fixture() as f:
                raw=(f.authority/".owner.json").read_bytes()[:-1]+raw_suffix
                f.write(f.authority/".owner.json",raw);p=f.session("duplicate-owner-field-"+str(len(raw_suffix)))
                self.assertEqual(p.call(1)[0],17)
        with Fixture("v11") as f:
            f.record(phase="frozen",predecessor_state_root="missing")
            self.assertEqual(f.session("frozen-before-predecessor").call(1)[0],19)

    def test_04_predecessor_selection_and_identity(self):
        cases = [(lambda f:f.record(predecessor_state_root=None),22),
            (lambda f:f.record(predecessor_state_root="relative"),20),
            (lambda f:f.record(predecessor_state_root=str(f.state)),21),
            (lambda f:f.record(state_root=str(f.prior)),23),
            (lambda f:f.prior.chmod(0o755),20),
            (lambda f:f.prior.rmdir(),20)]
        for index,(setup,code) in enumerate(cases):
            with self.subTest(index=index),Fixture("v11") as f:
                setup(f);self.assertEqual(f.session("predecessor-"+str(index)).call(1)[0],code)
        with Fixture("v11") as f:
            f.record(owner="v11",predecessor_state_root="relative")
            p=f.session("predecessor-before-owner-mismatch",config={"HEPTA_EFFECT_OWNER_SELF":"v4"})
            self.assertEqual(p.call(1)[0],20)
        with Fixture("v11") as f:
            p=self.admit(f,"live-path-rebind")
            f.prior.rename(f.directory/"retained-prior");f.prior.mkdir(mode=0o700)
            self.assertEqual(p.call(2,"local","new")[0],25)
            self.assertEqual(p.call(3,"local","new")[0],25)
            self.assertEqual(p.call(4)[0],0)

    def test_05_process_query_domain_and_bypass(self):
        queries = [("local",None,26),("local","",27),("","key",27),("bad/host","key",27),
            ("é","key",27),("x"*129,"key",27),("local","é"*129,27),
            ("a-Z_0.9","é"*128,0),("x"*128,"k"*256,0),("local","new\0key",0)]
        with Fixture("v11") as f:
            f.jobs();p=self.admit(f,"process-domain")
            for host,key,code in queries:self.assertEqual(p.call(2,host,key)[0],code)
            self.assertEqual(p.call(4)[0],0)
        with Fixture() as f:
            p=self.admit(f,"v4-domain-bypass")
            for host,key,_ in queries:self.assertEqual(p.call(2,host,key)[0],0)
            self.assertEqual(p.call(4)[0],0)

    def test_06_predecessor_records(self):
        cases = [
            (lambda f:f.job(key="old"),"old",34),
            (lambda f:f.job(key="old"),"new",0),
            (lambda f:f.job(key=None,request_digest="not validated without a key"),"new",0),
            (lambda f:f.job(key=""),"new",45),
            (lambda f:f.job(key="k"*257),"new",45),
            (lambda f:f.job(request_digest=None),"new",45),
            (lambda f:f.job(request_digest="A"*64),"new",45),
            (lambda f:f.job(request_digest="g"*64),"new",45),
            (lambda f:f.job(request_digest="0"*63),"new",45),
            (lambda f:f.job(id="different"),"new",44),
            (lambda f:f.job(host="bad/host"),"new",44),
            (lambda f:f.job(host=""),"new",44),
            (lambda f:f.job(host="x"*129),"new",44),
            (lambda f:f.job(key=None,request_digest=0),"new",43),
            (lambda f:f.write(f.jobs()/"one.json",b"{}"),"new",43),
            (lambda f:f.write(f.jobs()/"one.json",b""),"new",39),
            (lambda f:f.write(f.jobs()/"one.json",b" "*(1048577)),"new",39),
            (lambda f:f.write(f.jobs()/".temporary",b"{}"),"new",37),
            (lambda f:f.write(f.jobs()/("x"*136+".json"),b"{}"),"new",37),
            (lambda f:(f.job("one"),f.job("two")),"new",46),
            (lambda f:f.job("one",name="one.json.json"),"old",34),
            (lambda f:f.jobs().chmod(0o755),"new",31),
            (lambda f:f.job().chmod(0o640),"new",12),
            (lambda f:os.link(f.job(),f.directory/"linked-job"),"new",12),
        ]
        for index,(setup,key,code) in enumerate(cases):
            with self.subTest(index=index),Fixture("v11") as f:
                setup(f);p=self.admit(f,"job-"+str(index))
                self.assertEqual(p.call(2,"local",key)[0],code)
                self.assertEqual(p.call(4)[0],0)
        with Fixture("v11") as f:
            f.jobs();path=os.fsencode(f.jobs())+b"/invalid-\xff.json"
            fd=os.open(path,os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600);os.close(fd)
            p=self.admit(f,"non-utf8-job-name")
            self.assertEqual(p.call(2,"local","new")[0],36)
            self.assertEqual(p.call(4)[0],0)
        for byte in (b"\xff",b"\\ud800"):
            with Fixture("v11") as f:
                raw=b'{"id":"one","host":"local","idempotency_key":null,"unknown":"'+byte+b'"}'
                f.write(f.jobs()/"one.json",raw);p=self.admit(f,"ignored-byte-"+byte.hex())
                self.assertEqual(p.call(2,"local","new")[0],0)
                self.assertEqual(p.call(4)[0],0)

    def test_07_replay_cache_state(self):
        with Fixture("v11") as f:
            one=f.job();p=self.admit(f,"cache-seal")
            self.assertEqual(p.call(2,"local","old")[0],34)
            self.assertEqual(p.call(2,"local","new")[0],0)
            one.write_bytes(b"malformed but same frozen directory identity")
            self.assertEqual(p.call(2,"local","new")[0],0)
            self.assertEqual(p.call(2,"local","old")[0],34)
            f.job("two",key="second")
            self.assertEqual(p.call(2,"local","new")[0],33)
            self.assertEqual(p.call(4)[0],0)
            f.write(one,json.dumps({"id":"one","host":"local","idempotency_key":None,"request_digest":None}).encode())
            f.record(epoch=8)
            self.assertEqual(p.call(1),(0,0,8,1))
            self.assertEqual(p.call(2,"local","old")[0],0)
            self.assertEqual(p.call(2,"local","second")[0],34)
            self.assertEqual(p.call(4)[0],0)
        with Fixture("v11") as f:
            f.jobs();bad=f.write(f.jobs()/"bad.json",b"{")
            p=self.admit(f,"failed-scan-does-not-publish")
            self.assertEqual(p.call(2,"local","new")[0],43)
            bad.unlink();f.job()
            self.assertEqual(p.call(2,"local","old")[0],34)
            self.assertEqual(p.call(4)[0],0)

    def test_08_pty_descriptor_lookup(self):
        with Fixture("v11") as f:
            p=self.admit(f,"pty-absent")
            self.assertEqual(p.call(3,"local",None)[0],48)
            self.assertEqual(p.call(3,"bad/host","new")[0],49)
            self.assertEqual(p.call(3,"local","new")[0],0)
            directory=f.prior/"terminals";directory.mkdir(mode=0o700)
            self.assertEqual(p.call(3,"local","new")[0],0)
            name="dpty-"+hashlib.sha256(b"local\0new").hexdigest()+".json"
            file=f.write(directory/name,b"invalid JSON is still an existing original terminal")
            self.assertEqual(p.call(3,"local","new")[0],53)
            self.assertEqual(p.call(3,"different","new")[0],0)
            file.chmod(0o640);self.assertEqual(p.call(3,"local","new")[0],12)
            file.chmod(0o600);directory.chmod(0o750)
            self.assertEqual(p.call(3,"local","new")[0],50)
            self.assertEqual(p.call(4)[0],0)
        with Fixture() as f:
            p=self.admit(f,"pty-v4-bypass")
            self.assertEqual(p.call(3,"",None)[0],0)
            self.assertEqual(p.call(4)[0],0)

    def test_09_real_shared_lock_lifetime(self):
        with Fixture() as f:
            p=self.admit(f,"shared-lock-first");second=self.admit(f,"shared-lock-second",close_stderr=True)
            with (f.authority/".owner.lock").open("rb") as lock:
                with self.assertRaises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertEqual(p.call(4)[0],0)
                with self.assertRaises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                second.close()
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                p.send(1)
                self.assertEqual(select.select([p.process.stdout],[],[],0.05)[0],[])
                fcntl.flock(lock,fcntl.LOCK_UN)
                self.assertEqual(p.receive(),(0,0,7,0))
                self.assertEqual(p.call(4)[0],0)
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                fcntl.flock(lock,fcntl.LOCK_UN)

    def test_10_original_registry_count_boundary(self):
        with Fixture("v11") as f:
            jobs=f.jobs()
            for i in range(65536):
                f.write(jobs/(str(i)+".json"),json.dumps({"id":str(i),"host":"local","idempotency_key":None,"request_digest":None},separators=(",",":")).encode())
            p=self.admit(f,"registry-65536")
            self.assertEqual(p.call(2,"local","new")[0],0)
            self.assertEqual(p.call(4)[0],0)
            f.job("extra",key=None)
            f.record(epoch=8)
            self.assertEqual(p.call(1),(0,0,8,1))
            self.assertEqual(p.call(2,"local","new")[0],38)
            self.assertEqual(p.call(4)[0],0)


if __name__ == "__main__":
    began=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OwnerTests))
    path, identity, backend=executable()
    completion={"tests_run":result.testsRun,"expected_tests":10,"failures":len(result.failures),
        "errors":len(result.errors),"skipped":len(result.skipped),"expected_failures":len(result.expectedFailures),
        "unexpected_successes":len(result.unexpectedSuccesses)}
    passed=result.wasSuccessful() and result.testsRun==10 and not any(completion[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
    expected_counts={"processes":93,"closed_processes":93,"requests":212,"responses":212}
    counts_match=COUNTS==expected_counts and len(ROWS)==212
    passed=passed and counts_match
    raw=("\n".join(json.dumps(row,sort_keys=True,separators=(",",":")) for row in ROWS)+"\n").encode()
    report={"schema":"hepta.runtime.effect-fence-owner.serial-tests.v1","status":"PASS" if passed else "FAIL",
        **completion,"counts":COUNTS,"expected_counts":expected_counts,"counts_match":counts_match,"backend":backend,"binary_sha256":identity,
        "rows":len(ROWS),"raw_sha256":sha(raw),"elapsed_seconds":time.monotonic()-began,
        "sources":{name:sha((Path(__file__).parent/name).read_bytes()) for name in ("test_fence_owner.py","effect_fence_test_support.py")},
        "native_owner_calls":len(ROWS) if backend=="native-hia" else 0,
        "original_owner_calls":len(ROWS) if backend=="unchanged-original-rust" else 0,
        "concurrent_in_process_acquisition_qualified":False,"complete_effect_fence_owner":False,"whole_runtime_replaced":False}
    folder=os.environ.get("HIA_FENCE_CORPUS_DIR")
    if folder:
        folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
        (folder/"owner-cases.jsonl.gz").write_bytes(gzip.compress(raw,mtime=0))
        (folder/"owner-report.json").write_text(json.dumps(report,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True));sys.exit(0 if passed else 1)
