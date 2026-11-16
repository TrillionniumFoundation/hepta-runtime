"""Inert complete-buffer verification of the callable pack and observer-free ABI."""
import struct
from common import ROOT, loads, pin, read, require
from callable_contract import inputs, cases


def buffers(root, row, labels):
    require(set(row['buffers']) == set(labels), 'complete callable physical buffer set')
    result = {}
    for label, item in row['buffers'].items():
        require(item['file'] == row['name'] + '.' + label + '.bin', 'exact callable physical path')
        raw = read(root / item['file'])
        require(pin(raw) == {key: item[key] for key in ('bytes', 'sha256')}, 'complete callable buffer bytes')
        result[label] = raw
    return result


def emission(root, identity):
    folder = root / 'callable-emission'
    report = loads(read(folder / 'EMISSION.json'))
    composition = loads(read(ROOT / 'native/audit_controller_callable.composition.json'))
    controller = read(root / 'build/modules/audit-store-controller/module.image.bin')
    sync = read(root / 'emission/boundary.bin')
    request, image = inputs(controller, sync, composition)
    require(read(folder / 'callable.bin') == image, 'every composed instruction equals the frozen adapter and admitted HIA modules')
    require(report['schema'] == 'hepta.audit-controller-callable.emission.v1'
            and report['source_manifest_sha256'] == identity and report['composed_image'] == pin(image)
            and report['controller'] == pin(controller) and report['synchronization'] == pin(sync)
            and report['adapter'] == composition['adapter'] and report['native_calls'] == 9
            and report['refusals'] == 8 and report['runtime_rust_required'] is False
            and report['runtime_python_required'] is False and report['whole_runtime_replaced'] is False,
            'complete actual HIA callable emission binding')
    require(report['module_manifest'] == pin(read(root / 'build/modules/audit-controller-callable/manifest.json')),
            'actual HIA packer module binding')
    expected = cases(request, len(image))
    require(len(report['calls']) == len(expected), 'all actual HIA callable emitter calls')
    physical = 0
    for row, (name, wire, capacity, code) in zip(report['calls'], expected, strict=True):
        require(row['name'] == name and row['returned'] == code and row['output_capacity'] == capacity
                and row['workspace_capacity'] == 64, 'closed callable emission domain')
        raw = buffers(folder, row, ('input', 'output-before', 'output-after', 'workspace-before', 'workspace-after'))
        require(raw['input'] == wire and raw['output-before'] == b'\xa5' * (capacity + 16)
                and raw['workspace-before'] == raw['workspace-after'] == b'\xa5' * 64 + b'\x5a' * 16,
                'complete input and unmodified physical workspace')
        require(raw['output-after'] == (image + b'\xa5' * (capacity + 16 - len(image))
                                       if name == 'valid' else raw['output-before']),
                'complete callable output including every unused byte')
        physical += sum(map(len, raw.values()))
    return dict(image=pin(image), calls=9, refusals=8, physical_bytes=physical)


def observer_free(root, identity, expected_pid):
    from read_capture import check_actor, check_queue, words
    folder = root / 'observer-free'
    report = loads(read(folder / 'CALLABLE.json'))
    image = read(root / 'callable-emission/callable.bin')
    require(report['schema'] == 'hepta.audit-controller-callable.observer-free.v1'
            and report['source_manifest_sha256'] == identity and report['image'] == pin(image)
            and report['pid'] == expected_pid and report['native_calls'] == 15
            and report['refusals'] == 9 and report['ordinary_calls'] == 6
            and report['observer_pointer'] == report['foreign_effect_calls'] == 0
            and report['runtime_rust_required'] is False and report['public_handler_qualified'] is False
            and report['whole_runtime_replaced'] is False, 'observer-free native process and closed domain')
    names = ['short', 'long', 'magic', 'external-resume', 'command', 'actor-capacity',
             'context-capacity', 'context-reserved', 'context-state', 'initialize',
             'exclusive-acquire', 'exclusive-drop', 'shared-acquire', 'shared-finish', 'destroy']
    require([row['name'] for row in report['calls']] == names, 'all observer-free calls exactly once')
    labels = [phase + '-' + label for phase in ('before', 'after')
              for label in ('input', 'actor', 'context', 'kernel', 'queue')]
    commands = dict(initialize=0, **{'external-resume': 3, 'command': 7, 'exclusive-acquire': 1,
                    'exclusive-drop': 5, 'shared-acquire': 2, 'shared-finish': 4, 'destroy': 6})
    ordinary, previous, physical = {}, None, 0
    for index, row in enumerate(report['calls']):
        name = row['name']
        raw = buffers(folder, row, labels)
        physical += sum(map(len, raw.values()))
        deadline = report['deadline'] if name == 'shared-acquire' else 0
        frame = [int.from_bytes(b'HAUCTL01', 'little'), commands.get(name, 0), 0, 0, 1,
                 int(bool(deadline)), deadline & ((1 << 64) - 1), deadline >> 64, *([0] * 24)]
        request = struct.pack('<32Q', *frame)
        if name == 'short': request = request[:-1]
        if name == 'long': request += b'\0'
        if name == 'magic': request = b'X' + request[1:]
        require(raw['before-input'] == raw['after-input'] == request + b'\xa5' * 16
                and row['request_bytes'] == len(request), 'every complete immutable ABI input')
        require(row['actor_capacity'] == (511 if name == 'actor-capacity' else 512)
                and row['context_capacity'] == (127 if name == 'context-capacity' else 128),
                'exact supplied native buffer capacities')
        require(0 < row['monotonic_before_ns'] <= row['monotonic_after_ns']
                and row['monotonic_after_ns'] - row['monotonic_before_ns'] < 60_000_000_000,
                'bounded actual ordinary native call')
        for phase in ('before', 'after'):
            for label, size in (('actor', 512), ('context', 128), ('kernel', 64)):
                value = raw[phase + '-' + label]
                require(len(value) == size + 16 and value[size:] == b'\xa5' * 16,
                        'complete observer-free protected physical buffer')
            context = words(raw[phase + '-context'][:128])
            require(context[2] > 0 and context[2] % 8 == 0 and context[3] == 64
                    and context[7:9] == (0, 0), 'no observer, foreign callback or hidden native driver')
        if index < 9:
            code = (0xfffffffe if name in ('actor-capacity', 'context-capacity')
                    else 0xfffffffd if name == 'context-state' else 0xffffffff)
            require(row['returned'] == code and all(raw['before-' + label] == raw['after-' + label]
                    for label in ('input', 'actor', 'context', 'kernel', 'queue')), 'every refusal preserves all bytes')
            require(raw['before-actor'] == b'\0' * 512 + b'\xa5' * 16
                    and raw['before-kernel'] == b'\0' * 64 + b'\xa5' * 16 and raw['before-queue'] == b'',
                    'fresh uninitialized refusal domain')
            state = list(words(raw['before-context'][:128]))
            state[2:4] = [0, 0]
            expected = [0] * 16
            if name == 'context-reserved': expected[9] = 1
            if name == 'context-state': expected[0] = 1
            require(state == expected, 'exact malformed context discriminator')
            continue
        if previous is not None:
            require(all(raw['before-' + label] == previous['after-' + label]
                        for label in ('context', 'kernel', 'queue')), 'complete cross-call shared-state byte chain')
        ordinary[name] = raw
        if name in ('initialize', 'exclusive-acquire', 'shared-acquire'):
            require(raw['before-actor'] == b'\0' * 512 + b'\xa5' * 16, 'fresh complete private callable actor')
        if name == 'initialize':
            require(raw['before-kernel'] == b'\0' * 64 + b'\xa5' * 16 and raw['before-queue'] == b'',
                    'uninitialized borrowed kernel and absent native queue')
            fresh = list(words(raw['before-context'][:128])); fresh[2:4] = [0, 0]
            require(fresh == [0] * 16, 'fresh complete native context descriptor')
        before_context = words(raw['before-context'][:128])
        context = words(raw['after-context'][:128])
        require(context[2:4] == before_context[2:4] and not any(context[7:]), 'external kernel pointer and zero callback state')
        if name == 'destroy':
            require(row['returned'] == 0 and raw['after-queue'] == b''
                    and all(context[i] == 0 for i in (0, 1, 4, 5, 6))
                    and raw['before-kernel'] == raw['after-kernel']
                    and raw['before-actor'] == raw['after-actor'], 'final native queue mapping disposal')
        else:
            require(row['returned'] == 512 and context[0] == int.from_bytes(b'HAPCTX01', 'little')
                    and context[1] == 1 and context[4] > 0 and context[4] % 4096 == 0
                    and context[5] == (128 if name == 'initialize' else 144) and context[6] == 4096,
                    'native context owns its actual mapped queue')
            actor = check_actor(raw['after-actor'], 1)
            expected_result = 3 if name.endswith('acquire') else 0
            require(actor[1:3] == (0, expected_result), 'completed observer-free HIA actor result')
            queue, waiting = check_queue(raw['after-queue'], context[5], 1)
            next_ticket = 0 if name == 'initialize' else 1 if name.startswith('exclusive') else 2
            require(queue[1] == next_ticket and queue[2] == int(name == 'exclusive-acquire')
                    and queue[3] == int(name == 'shared-acquire') and not waiting and queue[4] == 0,
                    'actual observer-free FIFO and guard state')
            kernel = words(raw['after-kernel'][:64])
            held = int(name == 'exclusive-acquire')
            sequence = dict(initialize=0, **{'exclusive-acquire': 0, 'exclusive-drop': 1,
                                             'shared-acquire': 2, 'shared-finish': 3})[name]
            require(kernel == (int.from_bytes(b'HASYNC01', 'little'), 0, held, sequence,
                               0, expected_pid if held else 0, 1, 0), 'exact actual mutex, thread and wake sequence')
        previous = raw
    for after, before in (('exclusive-acquire', 'exclusive-drop'), ('shared-acquire', 'shared-finish'),
                          ('initialize', 'destroy')):
        require(ordinary[after]['after-actor'] == ordinary[before]['before-actor'], 'private actor retained across API calls')
    shared = report['calls'][12]
    require(0 < report['deadline'] - shared['monotonic_before_ns'] <= 2_000_000_000,
            'shared request uses its actual future monotonic deadline')
    return dict(calls=15, refusals=9, ordinary_calls=6, observer_pointer=0,
                foreign_effect_calls=0, physical_bytes=physical, complete_native_queue_disposal=True)
