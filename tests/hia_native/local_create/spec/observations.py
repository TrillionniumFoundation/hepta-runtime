"""Decode complete native Local Create observations without inventing Rust events."""
import struct


def words(raw, count, offset=0):
    return struct.unpack_from('<' + 'Q' * count, raw, offset)


def cache_observation(raw):
    raw = bytes(raw)
    assert raw[:8] == b'HLCSNA01' and len(raw) >= 112
    extent, phase, capacity, used, reserved = words(raw, 5, 8)
    assert extent == len(raw) == capacity + 48 and phase in (0, 1) and reserved == 0
    arena = raw[48:]
    assert arena[:8] == b'HVCSTA01' and 64 <= used <= capacity
    version, arena_used, count, poison, *reserved = words(arena, 7, 8)
    assert version == 1 and arena_used == used and poison in (0, 1) and not any(reserved)
    at, entries = 64, {}
    for _ in range(count):
        assert used - at >= 16
        keylen, valuelen = words(arena, 2, at)
        at += 16
        assert keylen <= used - at and valuelen <= used - at - keylen and valuelen <= 1 << 20
        key, value = arena[at:at + keylen], arena[at + keylen:at + keylen + valuelen]
        key.decode('utf-8'); value.decode('utf-8')
        assert key not in entries
        entries[key] = value
        at += keylen + valuelen
    assert at == used and not any(arena[used:]), 'retired or unowned cache payload remains'
    return dict(phase=phase, poisoned=bool(poison), entries=entries)


def observations(raw):
    raw = bytes(raw)
    at, snapshots, records, sequence = 0, [], [], []
    child_sequence, generation = 0, None
    effect_sequences = {b'HLCREF01': 0, b'HSHMKFX1': 0}
    while at < len(raw):
        assert len(raw) - at >= 16
        magic = raw[at:at + 8]
        if magic == b'HLCSNA01':
            extent, = words(raw, 1, at + 8)
        else:
            assert magic in (b'HLCSPFX1', b'HLCASR01', b'HLCREF01', b'HSHMKFX1'), magic
            extent = {b'HLCSPFX1': 64, b'HLCASR01': 128, b'HLCREF01': 96, b'HSHMKFX1': 96}[magic]
        assert 16 <= extent <= len(raw) - at
        current = raw[at:at + extent]
        fields = words(current, (extent - 8) // 8, 8) if magic != b'HLCSNA01' else ()
        if magic == b'HLCSNA01':
            snapshots.append(cache_observation(current))
            sequence.append(('cache', snapshots[-1]['phase']))
        elif magic == b'HLCSPFX1':
            full_extent, child, ordinal, current_generation, flags, request_bytes, zero = fields
            assert full_extent == 64 + request_bytes and zero == 0
            assert 1 <= child <= 7 and ordinal == child_sequence + 1 and current_generation > 0
            assert flags == (3 if child == 3 else 5 if child == 4 else 1)
            if generation is None:
                generation = current_generation
            assert generation == current_generation
            child_sequence = ordinal
            record = dict(magic=magic.decode(), child=child, sequence=ordinal, generation=generation,
                          request_bytes=request_bytes, flags=flags)
            records.append(record); sequence.append(('child', child))
        elif magic == b'HLCASR01':
            size, action, life, current_generation, ordinal, accepted, completed, kind, error, start, end, phase, token, flags, zero = fields
            assert size == 128 and zero == 0 and 0 <= action <= 12 and 1 <= life <= 6
            assert generation is not None and current_generation == generation
            assert kind in (0, 1, 2) and error <= 4095
            assert kind != 2 or error == 0
            parent_phase = (flags >> 16) & 255
            assert 1 <= parent_phase <= 6 and (flags >> 25) == 0
            records.append(dict(magic=magic.decode(), action=action, life=life, generation=current_generation,
                sequence=ordinal, accepted=accepted, completed=completed, result_kind=kind, error=error,
                ticket_start=start, ticket_end=end, phase=phase, token=token, flags=flags,
                parent_phase=parent_phase))
            sequence.append(('async', action))
        else:
            ordinal, action, a, b, c, d, ready, value, error, token, zero = fields
            # HSHMKFX1 has its ready word at 48, unlike the leaf effect at 56.
            if magic == b'HSHMKFX1':
                ordinal, action, a, b, c, ready, value, error, token, zero1, zero = fields
                assert zero1 == 0 and action in (1, 2, 3, 4)
            else:
                assert action in (1, 2, 3)
            expected = effect_sequences[magic] + 1
            if ordinal != expected:
                # A dropped successful OPEN has prepared its next WRITE in
                # the unchanged leaf owner before orphan cleanup prepares
                # CLOSE. The one unexecuted WRITE is the only allowed gap.
                assert magic == b'HLCREF01' and action == 3 and ordinal == expected + 1
                previous = records[-1]
                assert previous['magic'] == 'HLCASR01' and previous['life'] == 4
                assert previous['action'] in (4, 8) and previous['phase'] == 3 and previous['token'] == 1
            assert ready == 1 and zero == 0
            assert error <= 4095
            effect_sequences[magic] = ordinal
            records.append(dict(magic=magic.decode(), sequence=ordinal, action=action, fields=list(fields)))
            sequence.append(('effect', magic.decode()))
        at += extent
    assert len(snapshots) == 2 and [row['phase'] for row in snapshots] == [0, 1]
    assert sequence[0] == ('cache', 0) and sequence[-1] == ('cache', 1)
    return snapshots, records
