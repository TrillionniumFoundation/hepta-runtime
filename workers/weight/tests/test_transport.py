"""Real JSONL/Unix-socket worker lifecycle and durable request recovery tests."""
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fixtures import fixture
from weight_runtime.artifacts import atomic_create
from weight_runtime.errors import canonical, digest
from weight_runtime.patches import tensor_sha256
from weight_runtime.providers import load_provider
from weight_runtime.transport import Dispatcher

WORKER = Path(__file__).resolve().parents[1] / "worker.py"


class RecoveryTests(unittest.TestCase):
    def spent_session(self, root):
        params = fixture(root)
        params["limits"] = {"max_forward_examples": 1, "max_patch_candidates": 1}
        opened = {"id": "open", "op": "open", "params": params}
        dispatcher = Dispatcher("recovery")
        self.assertTrue(dispatcher.handle(opened)["ok"])
        probe = dispatcher.handle({"id": "spent-forward", "op": "probe",
                                   "params": {"inputs": {"x": [[2., 1.]]}}})
        self.assertTrue(probe["ok"], probe)
        provider = dispatcher.session.provider
        candidate = dispatcher.handle({"id": "spent-patch", "op": "patch", "params": {
            "expected_model_id": provider.model_id,
            "operations": [{"tensor": "0.weight", "operation": "scale", "indices": [0], "factor": 0.5,
                            "expected_tensor_sha256": tensor_sha256(provider.get_tensor("0.weight"))}]}})
        self.assertTrue(candidate["ok"], candidate)
        dispatcher.session.close({})
        return opened, dispatcher.ledger

    def assert_failed_admission(self, dispatcher, expected_forwards=0, expected_patches=0):
        self.assertIsNone(dispatcher.session.provider)
        self.assertIsNone(dispatcher.session.store)
        self.assertIsNone(dispatcher.session.policy)
        self.assertTrue(dispatcher.session.closed)
        response = dispatcher.handle({"id": "after-failed-admission", "op": "probe",
                                      "params": {"inputs": {"x": [[2., 1.]]}}})
        self.assertFalse(response["ok"], response)
        self.assertEqual(response["error"]["code"], "SESSION_STATE")
        self.assertEqual(dispatcher.session.forward_examples, expected_forwards)
        self.assertEqual(dispatcher.session.patch_candidates, expected_patches)

    def test_recovery_backend_drift_closes_real_provider_and_keeps_spent_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            opened, ledger = self.spent_session(Path(directory))
            receipt = ledger / (digest("open") + ".done.json")
            original_receipt = receipt.read_bytes()
            original_state = (ledger.parent / "session.json").read_bytes()
            loaded = []
            def drifted(*args):
                provider = load_provider(*args)
                provider.backend_id = digest({"injected": "backend drift"})
                loaded.append(provider)
                return provider
            recovered = Dispatcher("recovery")
            with patch("weight_runtime.providers.load_provider", side_effect=drifted):
                response = recovered.handle(opened)
            self.assertFalse(response["ok"], response)
            self.assertEqual(response["error"]["code"], "IDENTITY_MISMATCH")
            self.assertEqual(Path(response["error"]["details"]["path"]).name, "session.json")
            self.assertEqual(len(loaded), 1)
            self.assertIsNone(loaded[0].module)
            self.assertEqual(loaded[0].parameters, {})
            self.assertEqual(receipt.read_bytes(), original_receipt)
            self.assertEqual((ledger.parent / "session.json").read_bytes(), original_state)
            self.assert_failed_admission(recovered, 1, 1)

    def test_successful_recovery_keeps_exhausted_forward_and_patch_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            opened, _ = self.spent_session(Path(directory))
            recovered = Dispatcher("recovery")
            response = recovered.handle(opened)
            self.assertTrue(response["ok"], response)
            try:
                probe = recovered.handle({"id": "new-forward", "op": "probe",
                                          "params": {"inputs": {"x": [[2., 1.]]}}})
                self.assertEqual(probe["error"]["code"], "FORWARD_BUDGET")
                candidate = recovered.handle({"id": "new-patch", "op": "patch", "params": {
                    "expected_model_id": recovered.session.provider.model_id, "operations": []}})
                self.assertEqual(candidate["error"]["code"], "PATCH_BUDGET")
                self.assertEqual(recovered.session.forward_examples, 1)
                self.assertEqual(recovered.session.patch_candidates, 1)
            finally:
                recovered.session.close({})

    def test_recovery_runtime_error_and_cleanup_error_still_detach_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            opened, _ = self.spent_session(Path(directory))
            loaded = []
            def broken_description(*args):
                provider = load_provider(*args)
                real_close = provider.close
                def close_then_fail():
                    real_close()
                    raise RuntimeError("injected provider close failure")
                provider.close = Mock(side_effect=close_then_fail)
                provider.describe = Mock(side_effect=RuntimeError("injected post-load describe failure"))
                loaded.append(provider)
                return provider
            recovered = Dispatcher("recovery")
            with patch("weight_runtime.providers.load_provider", side_effect=broken_description):
                response = recovered.handle(opened)
            self.assertFalse(response["ok"], response)
            self.assertEqual(response["error"]["code"], "MODEL_EXECUTION_ERROR")
            self.assertIn("post-load describe failure", response["error"]["message"])
            loaded[0].close.assert_called_once()
            self.assertIsNone(loaded[0].module)
            self.assert_failed_admission(recovered, 1, 1)

    def test_initial_open_identity_failure_and_its_replay_both_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            params = fixture(Path(directory))
            params["expected_model_id"] = "0" * 64
            request = {"id": "open", "op": "open", "params": params}
            loaded = []
            def tracked(*args):
                provider = load_provider(*args)
                loaded.append(provider)
                return provider
            dispatcher = Dispatcher("recovery")
            with patch("weight_runtime.providers.load_provider", side_effect=tracked):
                response = dispatcher.handle(request)
            self.assertEqual(response["error"]["code"], "IDENTITY_MISMATCH")
            self.assertIsNone(loaded[0].module)
            self.assert_failed_admission(dispatcher)
            recovered = Dispatcher("recovery")
            with patch("weight_runtime.providers.load_provider", side_effect=AssertionError("must not reload a rejected open")):
                self.assertEqual(recovered.handle(request), response)
            self.assert_failed_admission(recovered)

    def test_initial_open_completion_receipt_failure_closes_loaded_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            params = fixture(Path(directory))
            dispatcher = Dispatcher("recovery")
            loaded = []
            def tracked(*args):
                provider = load_provider(*args)
                loaded.append(provider)
                return provider
            def failed_completion(path, data):
                if path.name.endswith(".done.json"):
                    raise OSError("injected completion write failure")
                return atomic_create(path, data)
            with patch("weight_runtime.providers.load_provider", side_effect=tracked), \
                 patch("weight_runtime.transport.atomic_create", side_effect=failed_completion):
                response = dispatcher.handle({"id": "open", "op": "open", "params": params})
            self.assertFalse(response["ok"], response)
            self.assertEqual(response["error"]["code"], "INVALID_REQUEST")
            self.assertIsNone(loaded[0].module)
            self.assertTrue((dispatcher.ledger / (digest("open") + ".pending.json")).exists())
            self.assertFalse((dispatcher.ledger / (digest("open") + ".done.json")).exists())
            self.assert_failed_admission(dispatcher)

    def test_durable_idempotence_conflict_and_pending_do_not_recompute(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            params = fixture(root)
            d = Dispatcher("recovery")
            opened = {"id": "open", "op": "open", "params": params}
            self.assertTrue(d.handle(opened)["ok"])
            request = {"id": "one", "op": "probe", "params": {"inputs": {"x": [[2., 1.]]}}}
            first = d.handle(request)
            self.assertTrue(first["ok"], first)
            self.assertEqual(first, d.handle(request))
            self.assertEqual(d.session.forward_examples, 1)
            changed = {**request, "params": {"inputs": {"x": [[1., 9.]]}}}
            self.assertEqual(d.handle(changed)["error"]["code"], "IDEMPOTENCY_CONFLICT")
            pending = {"id": "uncertain", "op": "probe", "params": {"inputs": {"x": [[8., 3.]]}}}
            atomic_create(d.ledger / (digest("uncertain") + ".pending.json"),
                          canonical({"request_sha256": digest(pending), "request": pending}) + b"\n")
            self.assertEqual(d.handle(pending)["error"]["code"], "UNKNOWN_OPERATION_STATE")
            d.session.close({})
            recovered = Dispatcher("recovery")
            self.assertTrue(recovered.handle(opened)["ok"])
            self.assertEqual(recovered.session.forward_examples, 1)
            self.assertEqual(recovered.handle({**request, "id": "new"})["error"]["code"], "UNKNOWN_OPERATION_STATE")
            recovered.session.close({})


class SocketTests(unittest.TestCase):
    def test_entry_preserves_stricter_owner_thread_budget(self):
        script = ("import runpy,sys,os,json;sys.path.insert(0," + repr(str(WORKER.parent)) + ");"
                  "runpy.run_path(" + repr(str(WORKER)) + ");"
                  "print(json.dumps({k:os.environ[k] for k in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS','GOTO_NUM_THREADS')}))")
        environment = dict(os.environ, OMP_NUM_THREADS="1", MKL_NUM_THREADS="2", OPENBLAS_NUM_THREADS="8", GOTO_NUM_THREADS="2")
        result = subprocess.run([sys.executable, "-c", script], env=environment, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(json.loads(result.stdout).values()), {"1"})

    def test_native_and_python_logs_do_not_pollute_protocol_stdout(self):
        script = ("import sys,os,ctypes;sys.path.insert(0," + repr(str(WORKER.parent)) + ");"
                  "from weight_runtime.transport import model_logs_to_stderr\n"
                  "with model_logs_to_stderr():\n os.write(1,b'native log\\n');print('python log');ctypes.CDLL(None).printf(b'buffered native log')\n"
                  "print('{\"ok\":true}')\n")
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'{"ok":true}\n')
        self.assertIn(b"native log", result.stderr)
        self.assertIn(b"python log", result.stderr)
        self.assertIn(b"buffered native log", result.stderr)

    def test_daemon_stays_alive_after_one_stdin_request_and_serves_clients(self):
        try:
            check = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            check.close()
        except PermissionError:
            self.skipTest("This execution sandbox forbids AF_UNIX; run this test on the owned runtime host")
        with tempfile.TemporaryDirectory(prefix="hwt-") as directory:
            root = Path(directory)
            params = fixture(root)
            params["idle_timeout_s"] = 20
            sock = root / "worker.sock"
            process = subprocess.Popen([sys.executable, str(WORKER), "--serve", "--socket", str(sock),
                                        "--session-id", "socket-test", "--lifetime-s", "60"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.stdin.write(canonical({"id": "open", "op": "open", "params": params}) + b"\n")
                process.stdin.close()
                first = json.loads(process.stdout.readline())
                self.assertTrue(first["ok"], first)
                self.assertIsNone(process.poll())
                def call(request):
                    result = subprocess.run([sys.executable, str(WORKER), "--client", "--socket", str(sock),
                                             "--timeout-ms", "10000", "--connect-timeout-ms", "3000"],
                                            input=canonical(request) + b"\n", stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, timeout=15)
                    return json.loads(result.stdout)
                request = {"id": "probe", "op": "probe", "params": {"inputs": {"x": [[2., 1.]]}}}
                result = call(request)
                self.assertTrue(result["ok"], result)
                self.assertEqual(result, call(request))
                ref = result["result"]["outputs"]["artifact_id"]
                view = call({"id": "view", "op": "query", "params": {"artifact_id": ref, "tensor": "output"}})
                self.assertEqual(view["result"]["values"], [2.5, .5])
                self.assertTrue(call({"id": "close", "op": "close", "params": {}})["ok"])
                self.assertEqual(process.wait(timeout=10), 0)
                self.assertFalse(sock.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                process.stdout.close()
                process.stderr.close()

    def test_hard_deadline_terminates_worker_process(self):
        script = ("import sys,time;sys.path.insert(0," + repr(str(WORKER.parent)) + ");"
                  "from weight_runtime.transport import Deadline\nwith Deadline(30): time.sleep(2)\n")
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 124)
        self.assertIn(b"request_deadline_exceeded", result.stderr)


if __name__ == "__main__":
    unittest.main()
