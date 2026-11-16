"""Read existing frames and complete buffers; never import or execute HIA."""
from pathlib import Path
import hashlib, json, struct

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


class Replay:
    def __init__(self, output):
        self.output = Path(output).resolve(strict=True)
        self.capture = json.loads((self.output / 'CAPTURE.json').read_bytes())
        assert self.capture['schema'] == 'hepta.sdk-request-tasks.native-capture.v1'
        assert self.capture['complete_mutable_buffers_retained']
        self.epoch = self.capture['epoch']
        self.calls = self.capture['calls']
        self.projections = self.capture['projections']
        self.call_index = self.projection_index = 0
        self.last_workspace = self.last_output = b''
        self.last_row = None
        self.read_paths = {'CAPTURE.json'}

    def read(self, pin):
        name = pin['path']
        assert Path(name).name == name and name not in ('', '.', '..')
        path = self.output / name
        assert path.is_file() and not path.is_symlink()
        raw = path.read_bytes()
        assert len(raw) == pin['bytes'] and SHA(raw) == pin['sha256'], name
        self.read_paths.add(name)
        return raw

    def project(self, wire):
        row = self.projections[self.projection_index]
        self.projection_index += 1
        raw = wire.encode()
        assert self.read(row['input']) == b'HRCJQ001' + struct.pack('<QQ', 1, len(raw)) + raw
        output = self.read(row['output'])
        self.read(row['workspace'])
        result = row['return_code']
        assert 256 <= result <= len(output) and output[:8] == b'HRCJR001'
        return output[:result]

    def invoke(self, operation, generation=0, arg0=0, arg1=0, payload=b''):
        frame = b'HRTKRQ01' + struct.pack('<7Q', operation, self.epoch,
            generation, arg0, arg1, len(payload), 0) + payload
        for _ in range(4):
            row = self.calls[self.call_index]
            self.call_index += 1
            assert self.read(row['input']) == frame
            before_o = self.read(row['before_output'])
            before_w = self.read(row['before_workspace'])
            if self.last_row:
                assert before_o[:len(self.last_output)] == self.last_output
                assert before_w[:len(self.last_workspace)] == self.last_workspace
                assert not any(before_o[len(self.last_output):])
                assert not any(before_w[len(self.last_workspace):])
                if self.last_row['return_code'] == 0xffffffd0:
                    kind, capacity, reserved = struct.unpack_from('<3Q', self.last_output, 8)
                    assert reserved == 0 and kind in (1, 2)
                    assert len(before_w) == (capacity if kind == 1 else len(self.last_workspace))
                    assert len(before_o) == (capacity if kind == 2 else len(self.last_output))
                    assert row['workspace_address'] != self.last_row['workspace_address']
                    assert row['output_address'] != self.last_row['output_address']
                else:
                    assert len(before_w) == len(self.last_workspace) and len(before_o) == len(self.last_output)
                    assert row['workspace_address'] == self.last_row['workspace_address']
                    assert row['output_address'] == self.last_row['output_address']
            else:
                assert not any(before_o) and not any(before_w)
            self.last_output = output = self.read(row['output'])
            self.last_workspace = self.read(row['workspace'])
            assert len(before_o) == len(output) == row['output_capacity']
            assert len(before_w) == len(self.last_workspace) == row['workspace_capacity']
            self.last_row = row
            result = row['return_code']
            if result == 0xffffffd0:
                assert output[:8] == b'HGRWS002'
                continue
            assert result == 160 and output[:8] == b'HRTKRS01'
            return struct.unpack('<20Q', output[:160])
        raise AssertionError('retained growth did not converge')

    def rows(self):
        raw = self.last_workspace
        if not raw:
            return []
        used = struct.unpack_from('<Q', raw, 72)[0]
        pos, result = 256, []
        while pos < used:
            fields = struct.unpack_from('<12Q', raw, pos)
            size, gen, live, cancel, done, response, send, delivery, kind, length, tag, job = fields
            assert all(v in (0, 1) for v in (live, cancel, done, response, send, delivery))
            assert size == (96 + length + 7) & ~7 and pos + size <= used
            assert not any(raw[pos + 96 + length:pos + size])
            result.append(dict(generation=gen, live=bool(live), cancelled=bool(cancel), done=bool(done),
                response_seen=bool(response), send_pending=bool(send), cancel_delivery_pending=bool(delivery),
                id_kind=kind, id=json.loads(raw[pos + 96:pos + 96 + length]), tag=tag, job=job))
            pos += size
        assert pos == used
        return result

    def close(self):
        assert self.call_index == len(self.calls) and self.projection_index == len(self.projections)
        assert self.read_paths == {p.name for p in self.output.iterdir() if p.is_file()}
        assert all(p.is_file() for p in self.output.iterdir())
