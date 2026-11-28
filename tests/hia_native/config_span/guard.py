"""Real guard/config/canonical ELF against complete frozen original Rust bytes."""
from pathlib import Path
import argparse
import hashlib
import gzip
import importlib.util
import io
import json
import os
import re
import signal
import stat
import struct
import subprocess
import time
import traceback

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
WORD = lambda raw, at: struct.unpack_from('<Q', raw, at)[0]
PACK = lambda *values: struct.pack('<'+'Q'*len(values), *values)
LITERALS = [b'cannot resolve directory move source identity', b'configured controller workspace root is unavailable',
            b'directory move would relocate a configured controller workspace root',
            b'runtime tools are disabled; start with --runtime-config <file>']


def pin(path):
    with path.open('rb') as stream:
        return {'bytes': path.stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def dump(path, value): path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')


def main():
    p = argparse.ArgumentParser(); p.add_argument('--build', type=Path, required=True); p.add_argument('--build-sha256', required=True); p.add_argument('--output', type=Path, required=True); p.add_argument('--oracle', type=Path, required=True); a = p.parse_args()
    a.build = a.build.resolve(strict=True)
    a.oracle = a.oracle.resolve(strict=True)
    a.output = a.output.resolve()
    a.output.mkdir(mode=0o700); started = time.monotonic(); processes = []; completed = []; f0_calls = 0; child_calls = 0
    dump(a.output/'remote-process.json', dict(pid=os.getpid(), cgroup=Path('/proc/self/cgroup').read_text(),
         uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(), cwd=str(Path.cwd())))
    manifest = a.build/'result.json'; assert pin(manifest)['sha256'] == a.build_sha256
    built = json.loads(manifest.read_bytes()); binary = Path(built['binary']); binary_before = pin(binary)
    assert binary_before['sha256'] == built['binary_sha256'] and built['installed_config_startup'] is True and len(built['members']) == 19
    bindings = build_inputs(built)
    dump(a.output/'SOURCE.json', dict(producer=pin(Path(__file__)), build=pin(manifest), binary=binary_before, inputs=bindings))
    fixture, snapshot, before, groups, provenance = prepare_original(a.output, a.oracle)
    report = dict(status='RUNNING', original_cases_compared=0, selected_cases=provenance['selected_cases'], excluded_private_abi_observations=len(provenance['excluded']), public_handler_complete=False, whole_runtime_replaced=False, fresh_original_comparison_complete=False, retained_original_bytes_compared=True)
    try:
        failures = []
        for name, roots, cases in groups:
            try:
                folder = a.output/name; folder.mkdir(mode=0o700)
                command = [str(binary)]
                if roots is not None:
                    state = folder/'state'; state.mkdir(mode=0o700)
                    config = json.dumps(dict(state_dir=str(state), controller_workspace_roots=roots,
                        hosts={'h': {'ssh_target': 'target', 'remote_state_dir': '/remote'}}), ensure_ascii=False, separators=(',', ':')).encode()
                    (folder/'config.json').write_bytes(config)
                    command += ['--runtime-config', str(folder/'config.json')]
                inputs = [b'HFDMGQ02'+PACK(1, len(path))+path for path, _ in cases]
                stdin = b''.join(PACK(7, len(frame))+frame for frame in inputs); (folder/'input.bin').write_bytes(stdin)
                argv = ['/usr/bin/strace', '-qq', '-f', '-s', '0', '-xx', '-o', str(folder/'kernel.trace'),
                        '-e', 'trace=readlink,readlinkat,newfstatat,statx,openat,close,write,getcwd,fcntl,mmap,mremap,munmap', *command]
                begin = time.monotonic(); timed = False
                with (folder/'input.bin').open('rb') as incoming, (folder/'stdout').open('xb') as stdout, (folder/'stderr').open('xb') as stderr:
                    process = subprocess.Popen(argv, cwd=fixture, stdin=incoming, stdout=stdout, stderr=stderr,
                                               env={'PATH': ''}, start_new_session=True)
                    try: code = process.wait(timeout=60)
                    except subprocess.TimeoutExpired: timed = True; os.killpg(process.pid, signal.SIGKILL); code = process.wait()
                receipt = dict(name=name, command=argv, executable_command=command, cwd=str(fixture), env={'PATH': ''},
                               pid=process.pid, timeout_seconds=60, timed_out=timed, exit_code=code,
                               elapsed_seconds=time.monotonic()-begin, stdin=pin(folder/'input.bin'),
                               stdout=pin(folder/'stdout'), stderr=pin(folder/'stderr'), kernel_trace=pin(folder/'kernel.trace'))
                processes.append(receipt); dump(a.output/'processes.json', processes)
                assert code == 0 and not timed, name
                raw = (folder/'stdout').read_bytes(); at = 0; totals = [0]*6; projected = []
                for ordinal, ((path, expected), frame) in enumerate(zip(cases, inputs, strict=True)):
                    assert len(raw)-at >= 96 and raw[at:at+8] == b'HRGFR002'
                    header = raw[at:at+96]; at += 96
                    assert (WORD(header, 8), WORD(header, 16)) == (7, 48), (name, WORD(header, 16))
                    size = WORD(header, 24); assert 48 <= size <= len(raw)-at
                    body = raw[at:at+size]; at += size
                    assert body[:8] == b'HFDMGR02' and WORD(body, 40) == 0
                    status, errno, top, chain = struct.unpack_from('<4Q', body, 8)
                    assert 48+top+chain == size
                    actual = (status, errno, body[48:48+top], body[48+top:])
                    assert actual == expected, (name, path[:128], actual)
                    counters = list(struct.unpack_from('<6Q', header, 32)); totals = [x+y for x,y in zip(totals,counters,strict=True)]
                    projected.append(dict(case_id=provenance["groups"][name][ordinal], input_bytes=len(frame), input_sha256=SHA(frame), full_body_bytes=len(body), full_body_sha256=SHA(body),
                                          status=status, errno=errno, short_bytes=top, chain_bytes=chain, counters=counters))
                assert at == len(raw)
                proof = trace_summary(folder/'stderr', projected)
                proof['configuration_growth_kernel'] = growth_kernel(folder/'kernel.trace', proof['configuration_growth'])
                dump(folder/'cases.json', projected)
                completed.append(dict(name=name, cases=len(projected), counters=totals, trace=proof)); f0_calls += totals[0]; child_calls += totals[3]
            except BaseException:
                failure = dict(group=name, case_ids=provenance["groups"][name], traceback=traceback.format_exc())
                failures.append(failure); dump(a.output/name/"FAILURE.json", failure)
        after = snapshot(); dump(a.output/'filesystem-after.json', after)
        assert before == after and pin(binary) == binary_before
        assert build_inputs(built) == bindings
        for path, value in provenance["bound_files"].items():
            assert pin(Path(path)) == value, ("source/capture changed", path)
        report.update(status='PASS' if not failures else 'FAIL', failed_groups=failures, original_cases_compared=sum(x['cases'] for x in completed), cases=sum(x['cases'] for x in completed), actual_elf_processes=len(processes),
                      actual_native_calls=f0_calls, actual_child_executions=child_calls,
                      fixture_before_after_equal=True, binary_unchanged=True, groups=completed)
        if failures: raise AssertionError("actual native groups failed; complete streams and successes retained")
    except BaseException:
        report.update(status='FAIL', failure=traceback.format_exc(), completed_groups=completed)
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic()-started
        dump(a.output/'RESULT.json', report)
    print(json.dumps({key:value for key,value in report.items() if key!='groups'}, sort_keys=True), flush=True)



CALL, GROW, DELIVERY = 0xfffffff0, 0xffffffd0, 0xffffffcd

def build_inputs(built):
    result = {}
    for name, value in built['sources'].items():
        assert pin(Path(name)) == value, ('actual boundary source', name)
        result[name] = value
    for member in built['members']:
        source = Path(member['source']); manifest = Path(member['manifest'])
        assert pin(source)['sha256'] == member['source_sha256'] and pin(manifest)['sha256'] == member['manifest_sha256']
        data = json.loads(manifest.read_bytes())
        image = manifest.parent/data['image']
        assert pin(image)['sha256'] == member['image_sha256']
        for path in (source, manifest, image): result[str(path)] = pin(path)
    return result

def growth_kernel(path, growth):
    pattern = re.compile(r'mremap\((0x[0-9a-f]+), ([0-9]+), ([0-9]+), MREMAP_MAYMOVE\) += (0x[0-9a-f]+)')
    actual = []
    with path.open('r', encoding='ascii') as stream:
        for line in stream:
            match = pattern.search(line)
            if match:
                old, before, after, new = match.groups()
                actual.append((int(old, 16), int(before), int(after), int(new, 16)))
    at = 0
    for row in growth:
        expected = (row['old_pointer'], row['old_capacity'], row['new_capacity'], row['new_pointer'])
        while at < len(actual) and actual[at] != expected: at += 1
        need(at < len(actual), ('recorded config growth binds actual mremap', expected))
        at += 1
    return dict(recorded_growth=len(growth), actual_mremap_calls=len(actual), ordered_all_bound=True)

def need(ok, label):
    if not ok:
        raise AssertionError(label)

def exact(stream, size, label):
    raw = stream.read(size)
    need(len(raw) == size, label)
    return raw

def trace_records(path):
    """Parse every byte; callers validate the recorded native transition sequence."""
    offset = 0
    with path.open("rb") as stream:
        while True:
            magic = stream.read(8)
            if not magic:
                return
            need(magic in (b"HRGTR002", b"HRCNAK02", b"HRCGRO02"), ("unexpected graph receipt", offset, magic))
            size = {b"HRGTR002":224, b"HRCNAK02":128, b"HRCGRO02":80}[magic]
            raw = magic + exact(stream, size - 8, "complete native graph receipt")
            yield offset, raw
            offset += size

def trace_summary(path, replies):
    """Bind child execution, delivery-only retries, actual effects, and all replies."""
    event_sequence = canonical_sequence = parent_sequence = 0
    pending_parent = pending_canonical = None
    counts = [0] * 6
    total = [0] * 6
    case = 0
    case_begin = 0
    case_effects = 0
    all_effects = 0
    rows = []
    call_slots = {}
    growth_phases = {}
    pending_growth = {}
    configuration_growth = []
    config_caps = [16 << 20, 32 << 20, 65536, 65536, 65536, 262144]
    config_pointers = {}
    for offset, raw in trace_records(path):
        if raw[:8] == b'HRCGRO02':
            seq, descriptor, selector, old, requested, new, raw_result, old_pointer, new_pointer = struct.unpack_from('<9Q', raw, 8)
            need(event_sequence == 0 and seq == len(configuration_growth)+1, 'ordered startup config growth')
            need(descriptor in range(6) and selector in range(5), 'config growth owned descriptor and child selector')
            need(old == config_caps[descriptor] and old < requested <= new, 'actual monotonically growing config borrow')
            expected = old
            while expected < requested: expected *= 2
            need(new == expected and old_pointer > 0 and new_pointer > 0 and old_pointer % 4096 == new_pointer % 4096 == 0 and raw_result == new_pointer,
                 'exact successful Linux config growth')
            if descriptor in config_pointers: need(old_pointer == config_pointers[descriptor], 'growth preserves actual owned mapping identity')
            config_caps[descriptor] = new; config_pointers[descriptor] = new_pointer
            configuration_growth.append(dict(sequence=seq, descriptor=descriptor, selector=selector, old_capacity=old, requested=requested, new_capacity=new,
                                             raw_syscall_result=raw_result, old_pointer=old_pointer, new_pointer=new_pointer))
            continue
        if raw[:8] == b"HRCNAK02":
            values = struct.unpack_from("<15Q", raw, 8)
            seq, phase, kind, path_offset, path_length, result, errno, got, input_at, canonical_at, link_at, link_cap, capacity, mode, done = values
            need(seq == canonical_sequence + 1 and done == seq, "actual canonical effect sequence")
            need(pending_canonical == (seq, phase, kind, path_offset, path_length), "actual canonical ACK binds requested effect")
            canonical_sequence = seq
            pending_canonical = None
            need(kind in range(1, 9) and (errno == 0 or 0 < errno <= 4095), "actual canonical syscall kind/error")
            signed = result - (1 << 64) if result >> 63 else result
            if errno:
                need(signed == -errno and got == 0, "exact syscall failure completion")
            elif kind == 4:
                need(signed == got and got <= link_cap and link_at + link_cap <= capacity,
                     "actual bounded readlink result")
            else:
                need(signed == 0 and got == 0, "actual stat success completion")
            case_effects += 1
            all_effects += 1
            continue
        seq, slot, event, code, work, out, phase, sequence, extent = struct.unpack_from("<9Q", raw, 8)
        need(seq == event_sequence + 1 and slot in (7, 8, 11) and event in (1, 2, 3, 4), "actual complete graph receipt order/domain")
        event_sequence = seq
        action = struct.unpack_from("<14Q", raw, 80)
        output = raw[192:224]
        if event == 1:
            need(slot not in pending_growth, "native retry follows recorded mechanical growth")
            counts[0] += 1
            call_slots[str(slot)] = call_slots.get(str(slot), 0) + 1
            if code == GROW:
                need(slot in (7, 8) and output[:8] == b"HGRWS002", "actual common owner growth request")
                kind, required, reserved = struct.unpack_from("<3Q", output, 8)
                need(kind in (1, 2) and reserved == 0 and required > (work if kind == 1 else out),
                     "exact native monotonic growth request")
                pending_growth[slot] = (kind, required, work, out, phase, sequence, output)
            elif slot == 11 and code == 0xfffffffe:
                # Frozen config op7 is an installed-state read. Its legacy
                # capacity refusal leaves the prior output unchanged, and the
                # admitted bridge only retries that uncompleted read.
                need(pending_parent is not None and pending_parent[2] == 1 and pending_parent[3] == 0,
                     "legacy config growth belongs to one unfinished read child")
                pending_growth[slot] = (2, out + 1, work, out, phase, sequence, output)
            if slot == 8 and code == CALL:
                need(pending_canonical is None and raw[80:88] == b"HRCANA02", "one pending canonical effect")
                pending_canonical = (action[1], phase, action[2], action[4], action[5])
            if slot == 7 and code == 48:
                need(case < len(replies) and phase == 0 and pending_parent is None and pending_canonical is None,
                     "completed original call has no pending child/effect")
                expected = replies[case]
                need(output[:8] == b"HFDMGR02" and struct.unpack_from("<3Q", output, 8) ==
                     (expected["status"], expected["errno"], expected["short_bytes"]), "actual parent header binds full stdout")
                need(counts == expected["counters"], (case, "all actual fixture counter deltas", counts, expected["counters"]))
                rows.append(dict(ordinal=case, offset=case_begin, end=offset + len(raw),
                                 counters=counts[:], actual_canonical_effects=case_effects))
                total = [a + b for a, b in zip(total, counts)]
                counts, case_effects = [0] * 6, 0
                case += 1
                case_begin = offset + len(raw)
        elif event == 2:
            need(slot in pending_growth and code == 0, "recorded successful growth has an actual preceding refusal")
            kind, required, old_work, old_out, old_phase, old_sequence, old_output = pending_growth.pop(slot)
            old_capacity = old_work if kind == 1 else old_out
            exact_capacity = (max(2 * old_capacity, required) + 4095) & ~4095
            need((work if kind == 1 else out) == exact_capacity and
                 (out if kind == 1 else work) == (old_out if kind == 1 else old_work),
                 "exact admitted bridge capacity change only")
            need(phase == old_phase and sequence == old_sequence and output == old_output,
                 "growth preserves continuation and complete prior output header")
            counts[kind] += 1
            key = str(slot) + ":" + str(phase) + ":" + str(kind)
            growth_phases[key] = growth_phases.get(key, 0) + 1
        elif event == 3:
            need(slot == 7 and pending_parent is None and raw[80:88] == b"HFDMGA02", "one native parent child")
            need(action[1] == parent_sequence + 1 and action[2] in (1, 2) and action[3] == 0,
                 "fresh native child only once")
            need(not any(action[8:]), "fresh native action has no forged completion")
            parent_sequence = action[1]
            pending_parent = action[:8]
            counts[3] += 1
        else:
            need(slot == 7 and pending_parent is not None and raw[80:88] == b"HFDMGA02", "child completion has actual execution")
            old = pending_parent
            need(action[1:3] == old[1:3] and action[4:6] == old[4:6] and action[8] == action[1] and
                 action[10] == action[11] == action[13] == 0, "exact original action completion")
            if action[3] == 1:
                counts[4] += 1
                need(old[3] == 1, "delivery retry follows short delivery only")
            else:
                need(action[3] == old[3] == 0, "first child result delivered once")
            if action[9] == DELIVERY:
                need(action[12] > action[7], "real complete child output exceeds destination")
                counts[5] += 1
                pending_parent = (old[0], old[1], old[2], 1, *old[4:])
            else:
                need(action[9] < 0xffff0000 and action[12] <= action[7], "complete child result delivered")
                pending_parent = None
    need(case == len(replies) and not any(counts) and pending_parent is None and pending_canonical is None and not pending_growth,
         "all actual graph transitions accounted for")
    return dict(rows=rows, common_records=event_sequence, counters=total,
                actual_canonical_effects=all_effects, native_calls_by_slot=call_slots,
                growth_phases=growth_phases, configuration_growth=configuration_growth)


def load_pinned(path, name, digest):
    assert pin(path)['sha256'] == digest, ("input helper differs", str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def prepare_original(output, source):
    source = source.resolve(strict=True)
    names = ('Cargo.lock', 'Cargo.toml', 'cases.py', 'golden/input.bin.gz',
             'golden/manifest.json', 'golden/responses.bin.gz', 'original/config.rs',
             'original/runtime.Cargo.lock', 'qualify.py', 'run.py', 'src/driver.rs',
             'strict_reference.py', 'test_reference_evidence.py', 'verify_sources.py')
    provenance = {'schema':'hepta.runtime.config-span-guard-golden.v1',
                  'original_source':str(source), 'new_rust_processes':0,
                  'fresh_original_comparison_complete':False,
                  'retained_original_bytes_compared':True, 'paths_replaced':False,
                  'selected_cases':0, 'groups':{}, 'excluded':[],
                  'bound_files':{str(source/name):pin(source/name) for name in names}}
    factory = load_pinned(source/'cases.py', '_guard_cases', 'fc80b0d0f09dafd00ecb51307761b4064acea4fa4f21ad23974479049e22811a')
    reader = load_pinned(source/'run.py', '_guard_original_reader', 'a3e770da5475243b2a25e6636b36036f14ad00d75c4dce3c1dd0ed601a88b235')
    assert pin(source/'golden/manifest.json')['sha256'] == '3f1b77b7fe052709d927c764f423ffa5b57234b2c331e81f4278087af989650b'
    assert pin(source/'golden/responses.bin.gz')['sha256'] == '9579e641771710dbcc6aca0130540cfbd972080903bc1457a8aba5819f220559'
    fixture = output/'fixtures'
    factory.setup(fixture)
    rows = factory.iter_cases(fixture)
    assert len(rows) == 92
    wire = io.BytesIO()
    factory.encode(wire, rows)
    raw_input = wire.getvalue()
    (output/'complete-original-domain-input.bin').write_bytes(raw_input)
    raw_output = gzip.decompress((source/'golden/responses.bin.gz').read_bytes())
    assert len(raw_output) == 15700 and SHA(raw_output) == '2dd340cc7ad260df8f813456ee9f956e606615b989bec53e298d666ccf44ae49'
    (output/'complete-original-golden-output.bin').write_bytes(raw_output)
    observations = reader.parse_output(raw_output, rows)
    before = factory.snapshot(fixture)
    provenance.update(fixture_root=str(fixture), complete_cases=92,
                      input_bytes=len(raw_input), input_sha256=SHA(raw_input),
                      response_bytes=len(raw_output), response_sha256=SHA(raw_output))
    dump(output/'filesystem-before.json', before)
    buckets = {}
    for case, observed in zip(rows, observations, strict=True):
        reason = None
        if not case['source'].startswith(b'/'):
            reason = 'source is outside the resolved absolute guard ABI'
        elif case['operation'] == 1:
            for root in case['roots']:
                if not root.startswith(b'/'):
                    reason = 'root is outside installed absolute configuration ABI'; break
                try: root.decode('utf-8')
                except UnicodeDecodeError:
                    reason = 'private raw PathBuf root cannot be supplied by UTF-8 JSON configuration'; break
        if reason:
            provenance['excluded'].append(dict(case_id=case['case_id'], name=case['name'], reason=reason, original=observed)); continue
        key = None if case['operation'] == 2 else tuple(case['roots'])
        buckets.setdefault(key, []).append((case, observed))
    groups = []
    for index, (roots, values) in enumerate(buckets.items()):
        name = 'group-%03d'%index; items = []; identifiers = []
        for case, observed in values:
            short = observed['short']['text'].encode(); chain = observed['chain']['text'].encode(); errno = observed['errno']
            if not observed['errno_present'] and chain == short+b': file name contained an unexpected NUL byte': errno = 65536
            items.append((case['source'], (observed['status'], errno, short, chain))); identifiers.append(case['case_id'])
        groups.append((name, None if roots is None else [root.decode('utf-8') for root in roots], items))
        provenance['groups'][name] = identifiers; provenance['selected_cases'] += len(items)
    excluded_ids = {60028, 60029, 60030, 60044, 60045, 60046, 60080, 60081, 60082, 60089, 60090}
    assert {row['case_id'] for row in provenance['excluded']} == excluded_ids
    selected_ids = [identifier for values in provenance['groups'].values() for identifier in values]
    assert len(groups) == 34 and provenance['selected_cases'] == len(selected_ids) == 81
    assert set(selected_ids) == set(range(60000, 60092)) - excluded_ids
    dump(output/'original-provenance.json', provenance)
    return fixture, lambda:factory.snapshot(fixture), before, groups, provenance


if __name__ == "__main__": main()
