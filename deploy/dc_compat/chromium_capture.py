# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bounded browser observations of SHA-bound local resources, under a caller's job.

The generated page performs fixed fetches; resource JavaScript/HTML is data and
is never evaluated. Only this call's private Chrome and loopback servers are
owned here. Durable requests, cancellation and recovery belong to native jobs.
"""
from __future__ import annotations

import base64
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import stat
import tempfile
import threading
import time

from .chromium_pdf import ChromeProtocolError, private_chrome

SCHEMA = 'hepta.rea.local-browser-capture.v1'
MAX_MANIFEST_BYTES = 64 * 1024
MAX_RESOURCES = 16
MAX_SOURCE_BYTES = 64 * 1024
MAX_TOTAL_SOURCE_BYTES = 2 * 1024 * 1024
MAX_REQUESTS = 32
MAX_ENTRIES = 64
MAX_BODY_BYTES = 64 * 1024
MAX_TOTAL_BODY_BYTES = 2 * 1024 * 1024
MAX_HAR_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_CDP_MESSAGES = 2048
MAX_CDP_MESSAGE_BYTES = 256 * 1024
MAX_CDP_BYTES = 8 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 60
ENTRY_PATH = '/__hepta_fixture__'
PROBE_PATH = '/__hepta_blocked__'
CONTROL_PATH = '/__hepta_control__'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _keys(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ValueError('Local capture object has missing or unsupported fields')


def _sha(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('Local capture requires a lowercase SHA-256 identity')
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('Duplicate JSON member in local capture manifest')
        result[key] = value
    return result


def _relative(value):
    if (not isinstance(value, str) or not value or len(value.encode('utf-8')) > 512
            or value.startswith('/') or '\\' in value or '\0' in value
            or any(part in ('', '.', '..') for part in value.split('/'))
            or len(value.split('/')) > 16):
        raise ValueError('Local capture file must be a normalized relative path')
    return value


@contextmanager
def _directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Local capture directory must be an absolute normalized path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        yield fd
    finally:
        os.close(fd)


def _read_at(directory, relative, maximum):
    parts = _relative(relative).split('/')
    parent = os.dup(directory)
    try:
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise ValueError('Local capture input is not a bounded regular file')
            data = source.read(maximum + 1)
            after = os.fstat(source.fileno())
            stamp = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if len(data) > maximum or stamp(before) != stamp(after) or len(data) != before.st_size:
                raise ValueError('Local capture input changed during its bounded read')
            return data
    finally:
        os.close(parent)


def load_manifest(path, expected_sha256):
    """Read each declared source once, with no symlink traversal or executable input."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Local capture manifest requires an absolute path')
    _sha(expected_sha256)
    with _directory(path.parent) as directory:
        raw = _read_at(directory, path.name, MAX_MANIFEST_BYTES)
        if digest(raw) != expected_sha256: raise ValueError('Local capture manifest SHA-256 mismatch')
        value = json.loads(raw, object_pairs_hook=_unique)
        _keys(value, ('schema', 'resources', 'requests'), ('timeout_seconds',))
        if value['schema'] != SCHEMA: raise ValueError('Unsupported local capture manifest schema')
        timeout = value.get('timeout_seconds', 30)
        if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError('Local capture timeout must be 1 through 60 seconds')
        if not isinstance(value['resources'], list) or not 1 <= len(value['resources']) <= MAX_RESOURCES:
            raise ValueError('Local capture resource count is outside its budget')
        resources, admitted, total = {}, {}, 0
        for resource in value['resources']:
            _keys(resource, ('url_path', 'mime_type', 'before'), ('after', 'delivery', 'delay_ms'))
            url = resource['url_path']
            if (not isinstance(url, str) or len(url) > 128 or re.fullmatch(r'/[A-Za-z0-9._/-]+', url) is None
                    or any(part in ('', '.', '..') for part in url[1:].split('/'))
                    or url.startswith('/__hepta_') or url in resources):
                raise ValueError('Local capture resource URL must be a distinct fixed path')
            mime = resource['mime_type']
            if not isinstance(mime, str) or not 1 <= len(mime) <= 128 or any(not 32 <= ord(c) <= 126 for c in mime):
                raise ValueError('Local capture MIME type is invalid')
            delivery, delay = resource.get('delivery', 'complete'), resource.get('delay_ms', 0)
            if delivery not in ('complete', 'truncated') or type(delay) is not int or not 0 <= delay <= 2000:
                raise ValueError('Local capture delivery mode or delay is outside its budget')
            sources = {}
            for phase in ('before', 'after'):
                declaration = resource.get(phase, resource['before'])
                _keys(declaration, ('file', 'sha256'))
                expected = _sha(declaration['sha256'])
                relative = _relative(declaration['file'])
                key = (relative, expected)
                if key not in admitted:
                    data = _read_at(directory, relative, MAX_SOURCE_BYTES)
                    if digest(data) != expected: raise ValueError('Local capture resource SHA-256 mismatch')
                    admitted[key] = data
                data = admitted[key]
                total += len(data)
                if total > MAX_TOTAL_SOURCE_BYTES: raise ValueError('Local capture total source bytes exceed the budget')
                sources[phase] = dict(file=declaration['file'], sha256=expected, data=data)
            resources[url] = dict(mime_type=mime, delivery=delivery, delay_ms=delay, **sources)
        requests = value['requests']
        if (not isinstance(requests, list) or not 1 <= len(requests) <= MAX_REQUESTS
                or any(not isinstance(url, str) or url not in resources for url in requests)):
            raise ValueError('Local capture requests must select 1 through 32 declared resources')
    return dict(parent=path.parent, manifest_path=str(path), manifest_sha256=expected_sha256,
                resources=resources, requests=requests, timeout_seconds=timeout)


class FixtureServers:
    """Two finite, call-owned loopback servers; the second proves the page gate."""
    def __init__(self, manifest):
        self.manifest, self.phase = manifest, 'before'
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = Counter()
        self.created = time.time()
        self.servers, self.threads = [], []

    def __enter__(self):
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args): pass
            def date_time_string(self, timestamp=None):
                return super().date_time_string(fixture.created)
            def do_GET(self):
                with fixture.lock:
                    phase = fixture.phase
                    fixture.counts[(self.server.kind, phase, self.path)] += 1
                if self.server.kind == 'probe':
                    body, mime, status, delivery, delay = b'owned-loopback-probe', 'text/plain', 200, 'complete', 0
                elif self.path == ENTRY_PATH:
                    body, mime, status, delivery, delay = fixture.page(), 'text/html; charset=utf-8', 200, 'complete', 0
                elif self.path in fixture.manifest['resources']:
                    item = fixture.manifest['resources'][self.path]
                    body, mime, status, delivery, delay = item[phase]['data'], item['mime_type'], 200, item['delivery'], item['delay_ms']
                else:
                    body, mime, status, delivery, delay = b'unknown fixture resource', 'text/plain', 404, 'complete', 0
                if fixture.stop.wait(delay / 1000):
                    self.close_connection = True; return
                try:
                    self.send_response(status)
                    self.send_header('Content-Type', mime)
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('Content-Length', str(len(body) + (delivery == 'truncated')))
                    self.send_header('Connection', 'close')
                    self.end_headers(); self.wfile.write(body); self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    self.close_connection = True
        try:
            for kind in ('source', 'probe'):
                server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                server.daemon_threads = True
                server.kind = kind
                self.servers.append(server)
                thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
                self.threads.append(thread); thread.start()
            self.origin = 'http://127.0.0.1:' + str(self.servers[0].server_port)
            self.probe_origin = 'http://127.0.0.1:' + str(self.servers[1].server_port)
            # A reachable second owned server is a stronger check than a DNS error.
            connection = http.client.HTTPConnection('127.0.0.1', self.servers[1].server_port, timeout=2)
            try:
                connection.request('GET', CONTROL_PATH)
                response = connection.getresponse()
                if response.status != 200 or response.read(128) != b'owned-loopback-probe':
                    raise ValueError('Owned negative-probe server failed its reachability control')
            finally:
                connection.close()
            return self
        except BaseException:
            self.__exit__(None, None, None); raise

    def page(self):
        paths = json.dumps(self.manifest['requests'])
        probe = json.dumps(self.probe_origin + PROBE_PATH)
        script = ('window.__heptaCaptureDone=(async()=>{const generation=window.__heptaCaptureGeneration;const results=[];for(const path of ' + paths
                  + '){try{const r=await fetch(path,{cache:"no-store",credentials:"omit"});'
                    'await r.arrayBuffer();results.push({path,ok:true})}catch(e){results.push({path,ok:false})}}'
                    'let blocked=false;try{await fetch(' + probe
                  + ',{mode:"no-cors",cache:"no-store",credentials:"omit"})}catch(e){blocked=true}'
                    'return {generation,results,blocked}})();')
        return ('<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,"><title>Hepta local capture</title>'
                '<script>' + script + '</script>').encode('utf-8')

    def probe_requests(self):
        with self.lock:
            return sum(count for (kind, _phase, path), count in self.counts.items()
                       if kind == 'probe' and path != CONTROL_PATH)

    def receipt(self):
        with self.lock:
            counts = [{'server': kind, 'phase': phase, 'path': path, 'count': count}
                      for (kind, phase, path), count in sorted(self.counts.items())]
        return dict(origin=self.origin, negative_probe_origin=self.probe_origin,
                    negative_probe_control_requests=1, negative_probe_browser_requests=self.probe_requests(),
                    request_counts=counts)

    def __exit__(self, *_):
        self.stop.set()
        for server in self.servers:
            server.shutdown(); server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


def _headers(value):
    if not isinstance(value, dict) or len(value) > 128:
        raise ValueError('CDP header inventory exceeds its budget')
    result = []
    for name, text in sorted(value.items()):
        if not isinstance(name, str) or not isinstance(text, str) or len(name) > 256 or len(text.encode('utf-8')) > 8192:
            raise ValueError('CDP header exceeds its budget')
        result.append(dict(name=name, value=text))
    return result


class Capture:
    def __init__(self, origin, resource_paths):
        self.allowed = {origin + path for path in resource_paths} | {origin + ENTRY_PATH}
        self.origin = origin
        self.rows, self.denied, self.phase = {}, [], 'before'
        self.body_bytes = 0

    def gate(self, url):
        if url not in self.allowed:
            if len(self.denied) >= MAX_ENTRIES: raise RuntimeError('Page origin denial count exceeds budget')
            self.denied.append(dict(phase=self.phase, url=str(url)[:4096]))
            raise ValueError('Request is outside this capture origin and declared paths')

    def event(self, message):
        method, value = message.get('method'), message.get('params', {})
        if not isinstance(method, str) or not method.startswith('Network.'): return
        identity = value.get('requestId')
        if method == 'Network.requestWillBeSent':
            if identity in self.rows: raise ValueError('Redirected request identities are outside the local capture contract')
            if len(self.rows) >= MAX_ENTRIES: raise ValueError('Browser request count exceeds its budget')
            request = value.get('request', {})
            # The generated inline favicon has no HTTP transaction to retain.
            if request.get('url') == 'data:,': return
            if request.get('method') != 'GET' or not isinstance(request.get('url'), str) or len(request['url']) > 4096:
                raise ValueError('Unexpected request in fixed local capture')
            self.rows[identity] = dict(request=request, start=value.get('timestamp', 0), wall=value.get('wallTime', time.time()))
        elif identity in self.rows:
            row = self.rows[identity]
            if method == 'Network.responseReceived': row['response'] = value['response']
            elif method == 'Network.loadingFinished': row.update(finished=True, end=value.get('timestamp', row['start']))
            elif method == 'Network.loadingFailed':
                row.update(failed=str(value.get('errorText', 'network loading failed'))[:256], end=value.get('timestamp', row['start']))

    def har(self, cdp):
        entries, states = [], Counter()
        identities = list(self.rows)
        for identity in identities:
            row = self.rows[identity]
            request, observed = row['request'], row.get('response', {})
            response = dict(status=int(observed.get('status', 0)), statusText=observed.get('statusText', ''),
                            httpVersion=observed.get('protocol', ''), headers=_headers(observed.get('headers', {})),
                            cookies=[], content=dict(mimeType=observed.get('mimeType', '')), redirectURL='', headersSize=-1, bodySize=-1)
            missing = row.get('failed') or 'request did not finish within the capture window'
            body_state = 'missing'
            representation_sha = decoded_sha = None
            if row.get('finished'):
                try:
                    body = cdp.call('Network.getResponseBody', {'requestId': identity})
                except ChromeProtocolError as error:
                    missing = str(error)[:256]
                else:
                    if (not isinstance(body.get('body'), str) or type(body.get('base64Encoded')) is not bool
                            or len(body['body'].encode('utf-8')) > MAX_BODY_BYTES * 2):
                        raise ValueError('Captured response representation exceeds its budget or has an invalid encoding')
                    encoded = body['body'].encode('utf-8')
                    decoded = base64.b64decode(body['body'], validate=True) if body['base64Encoded'] else encoded
                    self.body_bytes += len(decoded)
                    if len(decoded) > MAX_BODY_BYTES or self.body_bytes > MAX_TOTAL_BODY_BYTES:
                        raise ValueError('Captured response bodies exceed their byte budget')
                    response['content'].update(text=body['body'], size=len(decoded))
                    if body['base64Encoded']: response['content']['encoding'] = 'base64'
                    response['bodySize'] = len(decoded)
                    representation_sha, decoded_sha = digest(encoded), digest(decoded)
                    body_state = 'empty' if not decoded else 'base64' if body['base64Encoded'] else 'complete'
                    missing = None
            states[body_state] += 1
            entries.append(dict(startedDateTime=datetime.fromtimestamp(row['wall'], timezone.utc).isoformat(),
                time=max(0, (row.get('end', row['start']) - row['start']) * 1000),
                request=dict(method='GET', url=request['url'], httpVersion=observed.get('protocol', ''),
                             headers=_headers(request.get('headers', {})), cookies=[], queryString=[], headersSize=-1, bodySize=0),
                response=response, cache={}, timings=dict(send=0, wait=0, receive=0),
                _hepta=dict(body_state=body_state, body_missing_reason=missing,
                            representation_sha256=representation_sha, decoded_representation_sha256=decoded_sha,
                            network_loading_complete=bool(row.get('finished')), raw_wire_body_identity=False)))
        if list(self.rows) != identities:
            raise ValueError('Late browser requests changed the fixed capture inventory')
        return dict(log=dict(version='1.2', creator=dict(name='Hepta fixed local browser capture', version='1'),
                             entries=entries)), dict(entry_count=len(entries), body_states=dict(states),
                                every_response_body_recorded=states['missing'] == 0)


def encode(value, maximum):
    data = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(data) > maximum: raise ValueError('Final local capture artifact exceeds its encoded byte budget')
    return data


def completed_page(cdp, url, generation):
    # The old document has the same URL and an already-resolved promise. A
    # generation installed only for NEW documents must match before awaiting it.
    while True:
        ready = cdp.call('Runtime.evaluate', {'expression': '({url:document.URL,generation:window.__heptaCaptureGeneration,ready:!!window.__heptaCaptureDone})', 'returnByValue': True})
        value = ready.get('result', {}).get('value', {})
        if value.get('url') == url and value.get('generation') == generation and value.get('ready'):
            break
        time.sleep(.02)
    result = cdp.call('Runtime.evaluate', {'expression': 'window.__heptaCaptureDone', 'awaitPromise': True, 'returnByValue': True})
    actual = result.get('result', {}).get('value', {})
    if result.get('exceptionDetails') or actual.get('generation') != generation:
        raise ValueError('The fixed capture result does not belong to the current document generation')
    return actual


def publish_file(directory, name, data):
    """Create-only publication; a failure after linking is explicitly unconfirmed."""
    temporary = '.stage-' + os.urandom(16).hex()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    linked = False
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        linked = True
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
    except BaseException as error:
        try: os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError: pass
        if linked: raise RuntimeError('Capture artifact publication is unconfirmed; observe the original native job') from error
        raise


def capture(manifest, output_directory, progress=lambda _value: None, *, cancellation=None):
    output = Path(output_directory)
    if output.parent != manifest['parent'] or output.name in ('', '.', '..'):
        raise ValueError('Capture output must be a new direct child of the manifest directory')
    if output.exists() or output.is_symlink(): raise ValueError('Capture output directory already exists; never overwrite or rerun an uncertain job')
    phases = {}
    with FixtureServers(manifest) as fixture:
        observation = Capture(fixture.origin, manifest['resources'])
        with tempfile.TemporaryDirectory(prefix='.hepta-private-capture-', dir=manifest['parent']) as private:
            with private_chrome(private, resource_check=observation.gate, timeout_ms=manifest['timeout_seconds'] * 1000,
                    launch_timeout_ms=min(30000, manifest['timeout_seconds'] * 1000), event_sink=observation.event,
                    cleanup_guard=cancellation.defer if cancellation is not None else None,
                    message_limits=dict(max_messages=MAX_CDP_MESSAGES, max_message_bytes=MAX_CDP_MESSAGE_BYTES,
                                        max_received_bytes=MAX_CDP_BYTES)) as (cdp, process, profile):
                browser = cdp.call('Browser.getVersion')
                progress(dict(phase='browser_started', browser_pid=process.pid, browser_pgid=os.getpgid(process.pid), profile=str(profile), origin=fixture.origin,
                              negative_probe_origin=fixture.probe_origin))
                target = cdp.call('Target.createTarget', {'url': 'about:blank'})['targetId']
                cdp.session = cdp.call('Target.attachToTarget', {'targetId': target, 'flatten': True})['sessionId']
                cdp.call('Page.enable')
                cdp.call('Network.enable', {'maxTotalBufferSize': MAX_TOTAL_BODY_BYTES, 'maxResourceBufferSize': MAX_BODY_BYTES * 2})
                cdp.call('Network.setCacheDisabled', {'cacheDisabled': True})
                cdp.call('Network.setBypassServiceWorker', {'bypass': True})
                cdp.call('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]})
                bootstrap = None
                for phase in ('before', 'after'):
                    if bootstrap is not None:
                        cdp.call('Page.removeScriptToEvaluateOnNewDocument', {'identifier': bootstrap})
                    # This fixed bootstrap is controller-owned, never source JS
                    # or a caller-supplied CDP expression. It leaves HAR URLs and
                    # fixture response bytes identical across phase boundaries.
                    bootstrap = cdp.call('Page.addScriptToEvaluateOnNewDocument', {
                        'source': 'window.__heptaCaptureGeneration=' + json.dumps(phase) + ';'})['identifier']
                    fixture.phase = observation.phase = phase
                    observation.rows = {}
                    navigation = cdp.call('Page.navigate', {'url': fixture.origin + ENTRY_PATH})
                    if navigation.get('errorText'): raise ValueError('Private capture page navigation failed')
                    actual = completed_page(cdp, fixture.origin + ENTRY_PATH, phase)
                    if actual.get('blocked') is not True:
                        raise ValueError('The fixed page did not confirm its outside-origin request was blocked')
                    if len(actual.get('results', [])) != len(manifest['requests']):
                        raise ValueError('The fixed page did not finish its declared request inventory')
                    har, coverage = observation.har(cdp)
                    phases[phase] = (encode(har, MAX_HAR_BYTES), coverage)
                messages = dict(count=cdp.received_messages, bytes=cdp.received_bytes)
            # The shared owner has closed or killed only this call's Chrome group.
        if fixture.probe_requests() != 0:
            raise ValueError('An outside-origin browser request reached the owned negative-probe server')
        if not all(any(item['phase'] == phase and item['url'] == fixture.probe_origin + PROBE_PATH
                       for item in observation.denied) for phase in phases):
            raise ValueError('Missing observed page-gate denial for the owned reachable probe')
        server_receipt = fixture.receipt()
    source_pins = [{key: value for key, value in dict(url_path=url, mime_type=item['mime_type'], delivery=item['delivery'],
                    before=dict(file=item['before']['file'], sha256=item['before']['sha256'], bytes=len(item['before']['data'])),
                    after=dict(file=item['after']['file'], sha256=item['after']['sha256'], bytes=len(item['after']['data']))).items()}
                   for url, item in manifest['resources'].items()]
    artifacts = {phase: dict(path=str(output / (phase + '.har')), sha256=digest(data), bytes=len(data), **coverage)
                 for phase, (data, coverage) in phases.items()}
    receipt = dict(schema=SCHEMA, manifest_sha256=manifest['manifest_sha256'], source_resources=source_pins,
                   artifacts=artifacts, browser_version=browser, cdp_messages=messages, loopback=server_receipt,
                   denied_requests=observation.denied, private_chrome_closed=True, private_profile_removed=True,
                   original_process_group_no_live_members=True, changed_session_descendants_covered=False,
                   request_owner='existing native process job; no independent durable owner',
                   source_scripts_executed=False, generated_fixture_script_executed=True,
                   input_page_dom_inspected=False, arbitrary_page_execution_supported=False,
                   websocket_blocking_qualified=False, popup_navigation_blocking_qualified=False,
                   page_origin_gate=True, process_level_network_isolation=False,
                   same_origin_before_after=True, raw_http_wire_equivalence=False, general_browser_state_replay=False,
                   body_semantics='CDP response representation; missing body omitted; base64 kept encoded',
                   publication='create-only files; file and parent-directory fsync before success')
    receipt_bytes = encode(receipt, MAX_RECEIPT_BYTES)
    with _directory(manifest['parent']) as parent:
        os.mkdir(output.name, 0o700, dir_fd=parent)
        os.fsync(parent)
        directory = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            for phase, (data, _coverage) in phases.items(): publish_file(directory, phase + '.har', data)
            publish_file(directory, 'capture-receipt.json', receipt_bytes)
        finally:
            os.close(directory)
    return dict(schema=SCHEMA, receipt_path=str(output / 'capture-receipt.json'), receipt_sha256=digest(receipt_bytes),
                artifacts=artifacts, publication='confirmed', automatic_retry=False)


class _CancellationState:
    """Raise one cancellation outside owned setup/cleanup; defer it inside."""
    def __init__(self):
        self.requested = self.delivered = False
        self.depth = 0

    def _deliver(self):
        if self.requested and not self.delivered and self.depth == 0:
            self.delivered = True
            raise InterruptedError('Original native capture job was cancelled')

    def request(self, _signal, _frame):
        self.requested = True
        self._deliver()

    @contextmanager
    def defer(self):
        previous, failed = self.depth, False
        self.depth = previous + 1
        try:
            yield self
        except BaseException:
            failed = True
            raise
        finally:
            self.depth = previous
            # A cleanup error retains its unconfirmed status. Do not replace it
            # with cancellation. Otherwise deliver only after cleanup completed.
            if not failed: self._deliver()

    @contextmanager
    def interruptible(self):
        # Enter only under defer, before browser work. The enclosing owner's
        # finally remains protected even if the first signal arrives as this
        # inner context unwinds: that exception can be delivered only once.
        previous = self.depth
        if previous < 1: raise RuntimeError('Cancellation scope is not protected')
        try:
            self.depth = 0
            self._deliver()
            yield
        finally:
            self.depth = previous


@contextmanager
def cancellation_cleanup():
    """Let native job SIGTERM unwind only this worker's owned resources."""
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError('Capture cancellation handling requires its main thread')
    state = _CancellationState()
    previous = {number: signal.signal(number, state.request) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield state
    finally:
        for number, handler in previous.items(): signal.signal(number, handler)
