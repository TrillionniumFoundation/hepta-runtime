#!/usr/bin/env python3
"""One local control-flow check, not qualification or benchmark evidence.

Uses the frozen run_controller definition and the new main adapter with a tiny
owned Python stdin/EOF child. No runtime ELF, fixture dataset, MCP call, remote
action, qualification receipt or bound benchmark runner is produced.
"""
import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
BINDER = ROOT / 'bind_a50_archive_experiments.py'
TEMPLATE = ROOT / 'a46-bound/run_native_archive_cohort_a46_composed_r01.py'
EXPECTED_BINDER_SHA = 'a9300316db52fff333c0bb6a5120a2e06f5de62c387cf02e39de6e1b8e44ece2'
EXPECTED_TEMPLATE_SHA = 'a007f0ff0dee7ed5e981953a440070aa3bbb6980662c968ecd2bbdd7ebc8e029'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def execute(nodes, namespace):
    tree = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(tree, '<local-only-extracted-control-flow>', 'exec'), namespace)


def main():
    binder_raw, template_raw = BINDER.read_bytes(), TEMPLATE.read_bytes()
    assert digest(binder_raw) == EXPECTED_BINDER_SHA
    assert digest(template_raw) == EXPECTED_TEMPLATE_SHA
    binder = runpy.run_path(str(BINDER))  # Defines functions; never calls binder main.
    before = binder['relabel'](template_raw.decode())
    after = binder['large_main_custody_adapter'](before)
    old_tree, new_tree = ast.parse(before), ast.parse(after)

    def helpers(tree):
        return {node.name: ast.dump(node, include_attributes=False) for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != 'main'}

    assert helpers(old_tree) == helpers(new_tree) and len(helpers(old_tree)) == 38
    module = {'__name__': 'local_journal_fault_probe_only', '__file__': str(TEMPLATE)}
    exec(compile(new_tree, '<unbound-template-definitions-only>', 'exec'), module)
    main_node = next(node for node in new_tree.body
                     if isinstance(node, ast.FunctionDef) and node.name == 'main')
    adapter_defs = [node for node in main_node.body if isinstance(node, ast.FunctionDef)
                    and node.name in ('registered_controller', 'finish_owned_controllers')]
    assert len(adapter_defs) == 2
    controller_guard = next(node for node in ast.walk(main_node)
                            if isinstance(node, ast.Try) and node.body
                            and isinstance(node.body[0], ast.Assign)
                            and any(isinstance(target, ast.Name) and target.id == 'controller_complete'
                                    for target in node.body[0].targets))
    outer = next(node for node in main_node.body if isinstance(node, ast.Try))
    assert isinstance(outer.finalbody[0], ast.Expr)
    assert isinstance(outer.finalbody[1], ast.For)
    assert all(isinstance(node, ast.Try) for node in outer.finalbody[2:4])
    failure_gate = next(node for node in outer.finalbody if isinstance(node, ast.If)
                        and ast.dump(node.test) == ast.dump(ast.parse("report['errors']", mode='eval').body))
    passed_assignment = next(node for node in outer.finalbody if isinstance(node, ast.Assign)
                             and any(isinstance(target, ast.Subscript)
                                     and isinstance(target.value, ast.Name) and target.value.id == 'report'
                                     and isinstance(target.slice, ast.Constant) and target.slice.value == 'passed'
                                     for target in node.targets))

    class BrokenJournal:
        def __init__(self, path):
            self.stream = path.open('xb')
            self.flush_faults = 0
            self.close_calls = 0

        def write(self, value):
            return self.stream.write(value)

        def flush(self):
            self.flush_faults += 1
            raise OSError(errno.EIO, 'injected local journal flush failure')

        def fileno(self):
            return self.stream.fileno()

        def close(self):
            self.close_calls += 1
            self.stream.close()

    probes = []

    class OwnedPythonProbe:
        def __init__(self, binary, config, directory):
            self.directory = directory
            self.child, self.shutdown = None, None
            self.reaped, self.close_calls = False, 0
            self.startup = {'local_python_probe_only': True, 'native_mcp_calls': 0}
            probes.append(self)

        def start(self):
            self.child = subprocess.Popen(
                [sys.executable, '-c', 'import sys; sys.stdin.buffer.read()'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=self.directory, start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
            self.startup['pid'] = self.child.pid

        def initialize(self):
            pass  # No MCP initialize or runtime query is simulated as successful.

        def close(self):
            self.close_calls += 1
            assert self.close_calls == 1, 'the original close must never be invoked twice'
            self.child.stdin.close()
            pid, status, _usage = os.wait4(self.child.pid, 0)
            assert pid == self.child.pid
            self.child.returncode = os.waitstatus_to_exitcode(status)
            self.reaped = True
            self.child.stdout.close()
            self.child.stderr.close()
            self.shutdown = {'local_python_probe_only': True, 'original_child_reaped': True,
                             'waited': {'pid': pid, 'raw_wait_status': status,
                                        'exit_code': self.child.returncode},
                             'errors': [], 'reader_error': None, 'unmatched': []}
            return self.shutdown

    def make_fixture(directory):
        directory.mkdir()
        state = directory / 'empty-probe-state'
        state.mkdir()
        return directory / 'unused-probe-config', state

    def journal_failure_before_any_rpc(_controller, _rows, journal, **_kwargs):
        journal.flush()
        raise AssertionError('the deterministic journal fault was not raised')

    with tempfile.TemporaryDirectory(prefix='a50-local-custody-only-') as temporary:
        out = Path(temporary)
        journal = BrokenJournal(out / 'calls.jsonl')
        report = {'controllers': [], 'errors': [], 'complete': False, 'passed': False,
                  'original_controller_custody_adapter': []}
        module.update(Controller=OwnedPythonProbe, owned_controllers=[], report=report,
                      index=0, arm='A', bundles={'A': {'version': 'local-probe-not-a-runtime',
                      'binary': {'path': sys.executable, 'sha256': None}}}, out=out,
                      slots=[], waves=[], native=None, small=SimpleNamespace(make_fixture=make_fixture),
                      journal=journal, checkpoint=lambda: None,
                      observe_wave=journal_failure_before_any_rpc)
        execute(adapter_defs, module)
        try:
            try:
                execute([controller_guard], module)
            except OSError as error:
                assert error.errno == errno.EIO
            else:
                raise AssertionError('the original run_controller journal failure must propagate')
            assert len(probes) == 1
            probe = probes[0]
            assert probe.reaped and probe.close_calls == 1 and probe.child.returncode == 0
            state = module['owned_controllers'][0]
            assert state['close_attempted'] and state['close_returned'] and state['finalized']
            cleanup = report['original_controller_custody_adapter'][0]
            assert cleanup['fallback_used'] and not cleanup['close_attempted_before_fallback']
            assert report['controllers'][0]['status'] == 'failed' and report['errors']
            assert not report['complete'] and not report['passed']
            assert not any(key in report['controllers'][0] for key in
                           ('c1_process_cpu', 'c4_inclusive_cpu', 'fixture_after_shutdown',
                            'original_fixture_unchanged'))
            original_receipt = probe.shutdown
            assert probe.close() is original_receipt and probe.close_calls == 1
            module['finish_owned_controllers']()
            assert len(report['original_controller_custody_adapter']) == 1
            # Exercise the already-attempted/incomplete guard without another
            # child, original-close invocation, wait4, signal or replay.
            state['close_returned'] = False
            try:
                probe.close()
            except module['FatalExperiment']:
                pass
            else:
                raise AssertionError('an attempted incomplete close must be refused')
            assert probe.close_calls == 1
            state['close_returned'] = True

            # Isolate final-journal handling using the same fault and child.
            # These are synthetic control-flow flags, never a benchmark result.
            report.update(errors=[], complete=True, passed=True, phase='complete')
            execute(outer.finalbody[:4], module)
            execute([failure_gate, passed_assignment], module)
            assert not report['complete'] and not report['passed'] and report['phase'] == 'failed'
            assert any(error.startswith('journal_retain_interrupted_rows:') for error in report['errors'])
            assert any(error.startswith('journal_flush:') for error in report['errors'])
            assert journal.close_calls == 1 and journal.stream.closed
            assert report['calls_file']['bytes'] == 0
            assert probe.close_calls == 1 and probe.shutdown is original_receipt
            result = {
                'schema': 'hepta-a50-local-custody-control-flow-check/v1',
                'scope': 'One local journal-flush fault mode; one owned Python stdin/EOF child. Not qualification or benchmark evidence.',
                'passed': True, 'binder_sha256': digest(binder_raw),
                'template_sha256': digest(template_raw),
                'frozen_helper_ast_count': 38, 'frozen_helper_ast_unchanged': True,
                'original_run_controller_definition_exercised': True,
                'main_factory_and_per_controller_finally_exercised': True,
                'local_owned_children': 1, 'native_runtime_elf_executions': 0,
                'native_mcp_calls': 0, 'remote_actions': 0, 'qualification_bindings_emitted': 0,
                'formal_benchmarks_executed': 0, 'original_close_invocations': probe.close_calls,
                'original_wait4_receipt': original_receipt['waited'],
                'fallback_retained_failed_status': True,
                'already_attempted_close_not_reinvoked': True,
                'already_attempted_incomplete_close_refused': True,
                'cpu_fixture_or_slot_results_reconstructed': False,
                'final_journal_errors_retained': report['errors'],
                'journal_fault_encounters': journal.flush_faults,
                'journal_close_calls': journal.close_calls,
                'final_journal_error_forced_complete_and_passed_false': True,
            }
        finally:
            if not journal.stream.closed:
                journal.stream.close()
            for probe in probes:
                if probe.child is not None and not probe.reaped:
                    probe.child.kill()
                    _pid, status, _usage = os.wait4(probe.child.pid, 0)
                    probe.child.returncode = os.waitstatus_to_exitcode(status)
                    probe.reaped = True
    path = Path(__file__).with_name('local-journal-fault-check.json')
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'local_check': str(path), 'passed': True,
                      'bytes': path.stat().st_size, 'sha256': digest(path.read_bytes()),
                      'formal_benchmarks_executed': 0, 'qualification_bindings_emitted': 0}))


if __name__ == '__main__':
    main()
