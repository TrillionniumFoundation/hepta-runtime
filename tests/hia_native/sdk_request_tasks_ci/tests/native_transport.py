"""Call the actual two HIA images and retain every complete mutable buffer."""
from pathlib import Path
import ctypes, hashlib, json, struct, sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


class Registry:
    def __init__(self, source, build, output, epoch=1):
        self.source = Path(source).resolve(strict=True)
        self.build = Path(build).resolve(strict=True)
        self.output = Path(output).absolute()
        self.output.mkdir(parents=True, exist_ok=False)
        sys.path.insert(0, str(self.source / 'scripts'))
        from hia_native_loader import NativeModule
        receipt = json.loads((self.build / 'BUILD.json').read_text())
        self.modules = {}
        for name in ('request-tasks', 'request-tasks-message'):
            item = receipt['members'][name]
            self.modules[name] = NativeModule(self.build / item['manifest'],
                manifest_sha256=item['manifest_sha256'])
        self.session = self.modules['request-tasks'].session(
            output_capacity=160, workspace_capacity=256)
        self.epoch = epoch
        self.calls = []
        self.projections = []
        self.last_workspace = b''
        self.last_output = b''

    def put(self, path, raw):
        (self.output / path).write_bytes(raw)
        return dict(path=path, bytes=len(raw), sha256=SHA(raw))

    def project(self, wire):
        raw = wire.encode('utf-8')
        request = b'HRCJQ001' + struct.pack('<QQ', 1, len(raw)) + raw
        n = len(self.projections)
        result, output, workspace = self.modules['request-tasks-message'].invoke_raw(
            request, output_capacity=131072, workspace_capacity=1048576)
        row = dict(input=self.put(f'projection-{n}.input', request),
            output=self.put(f'projection-{n}.output', output),
            workspace=self.put(f'projection-{n}.workspace', workspace), return_code=result)
        self.projections.append(row)
        assert 256 <= result <= len(output) and output[:8] == b'HRCJR001', row
        return output[:result]

    def invoke(self, operation, generation=0, arg0=0, arg1=0, payload=b''):
        frame = b'HRTKRQ01' + struct.pack('<7Q', operation, self.epoch,
            generation, arg0, arg1, len(payload), 0) + payload
        for _ in range(4):
            before_output = self.session._output.raw[:self.session.output_capacity]
            before_workspace = self.session._workspace.raw[:self.session.workspace_capacity]
            result, output, workspace = self.session.invoke_raw(frame)
            n = len(self.calls)
            row = dict(input=self.put(f'call-{n}.input', frame),
                before_output=self.put(f'call-{n}.before-output', before_output),
                before_workspace=self.put(f'call-{n}.before-workspace', before_workspace),
                output=self.put(f'call-{n}.output', output),
                workspace=self.put(f'call-{n}.workspace', workspace),
                return_code=result, output_capacity=self.session.output_capacity,
                workspace_capacity=self.session.workspace_capacity,
                output_address=ctypes.addressof(self.session._output),
                workspace_address=ctypes.addressof(self.session._workspace))
            self.calls.append(row)
            self.last_workspace, self.last_output = workspace, output
            if result != 0xffffffd0:
                assert result == 160 and output[:8] == b'HRTKRS01', row
                return struct.unpack('<20Q', output[:160])
            assert output[:8] == b'HGRWS002'
            kind, capacity, reserved = struct.unpack_from('<3Q', output, 8)
            assert reserved == 0 and kind in (1, 2)
            old = self.session
            ocap, wcap = old.output_capacity, old.workspace_capacity
            assert capacity > (wcap if kind == 1 else ocap)
            self.session = self.modules['request-tasks'].session(
                output_capacity=capacity if kind == 2 else ocap,
                workspace_capacity=capacity if kind == 1 else wcap)
            ctypes.memmove(self.session._workspace, old._workspace, wcap)
            ctypes.memmove(self.session._output, old._output, ocap)
            old.close()
        raise AssertionError('growth did not converge')

    def rows(self):
        raw = self.last_workspace
        if not raw:
            return []
        used = struct.unpack_from('<Q', raw, 72)[0]
        pos, result = 256, []
        while pos < used:
            fields = struct.unpack_from('<12Q', raw, pos)
            size, generation, live, cancelled, done, response, send, cancel, kind, length, tag, job = fields
            assert size >= 96 + length and pos + size <= used
            assert not any(raw[pos + 96 + length:pos + size])
            result.append(dict(generation=generation, live=bool(live), cancelled=bool(cancelled),
                done=bool(done), response_seen=bool(response), send_pending=bool(send),
                cancel_delivery_pending=bool(cancel), id_kind=kind,
                id=json.loads(raw[pos + 96:pos + 96 + length]), tag=tag, job=job))
            pos += size
        assert pos == used
        return result

    def close(self):
        receipt = dict(schema='hepta.sdk-request-tasks.native-capture.v1',
            epoch=self.epoch, calls=self.calls, projections=self.projections,
            complete_mutable_buffers_retained=True)
        (self.output / 'CAPTURE.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        self.session.close()
        for module in self.modules.values():
            module.close()
