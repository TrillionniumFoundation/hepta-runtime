# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Private loopback MCP owner, independent of client/facade lifetimes."""
from __future__ import annotations
import asyncio
import contextvars
import hashlib
import hmac
import http.server
import json
import secrets
import threading
import time
from .server import CompatServer
from .journal import encode
from .input_context import INPUT_CLIENT

RPC_KEY = contextvars.ContextVar('hepta_operator_rpc_key', default=None)
VERSIONS = ('2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25')


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON member')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('nonfinite JSON number')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    # JSON's exponent syntax can overflow Python floats without invoking
    # parse_constant (for example 1e309). Reject it before durable admission.
    encode(value)
    return value


class JournalSession(CompatServer):
    def __init__(self, engine, identity):
        super().__init__(engine.registry, name='hepta-computer-operator', version='12')
        self.engine, self.identity, self.last_seen = engine, identity, time.monotonic()

    async def invoke(self, name, arguments):
        return await self.engine.call(name, arguments, RPC_KEY.get())

    async def dispatch(self, request):
        key = None
        if isinstance(request, dict) and 'id' in request and type(request['id']) in (int, str):
            key = self.identity + ':' + type(request['id']).__name__ + ':' + str(request['id'])
        token = RPC_KEY.set(key)
        input_token = INPUT_CLIENT.set(self.identity)
        try:
            if isinstance(request, dict) and request.get('method') == 'initialize':
                params = request.get('params', {})
                client = params.get('clientInfo', {}) if isinstance(params, dict) else {}
                if isinstance(client, dict):
                    self.engine.current_client = client
                    self.engine.journal.observe_client(client)
            self.last_seen = time.monotonic()
            return await super().dispatch(request)
        finally:
            INPUT_CLIENT.reset(input_token)
            RPC_KEY.reset(token)


class OperatorHTTP:
    def __init__(self, engine, token, *, port=0, maximum_request=16 * 1024 * 1024):
        if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError('private ASCII bearer token required')
        self.engine, self.token, self.maximum_request = engine, token, maximum_request
        self.maintenance_lease = None
        self.sessions, self.sessions_lock = {}, threading.RLock()
        self.loop = asyncio.new_event_loop()
        self.loop_thread = threading.Thread(target=self._run_loop, name='hepta-computer-owner', daemon=True)
        self.loop_thread.start()
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def setup(self):
                super().setup()
                self.connection.settimeout(15)

            def reply(self, status, value=None, session=None, raw=None):
                body = raw if raw is not None else b'' if value is None else encode(value)
                self.send_response(status)
                if body:
                    self.send_header('Content-Type', 'application/json' if raw is None else 'text/plain')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                if session:
                    self.send_header('Mcp-Session-Id', session)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def authenticated(self):
                supplied = self.headers.get('X-Hepta-Runtime-Token')
                authorization = self.headers.get('Authorization', '')
                if supplied is None and authorization.startswith('Bearer '):
                    supplied = authorization[7:]
                if not isinstance(supplied, str) or not supplied.isascii() or not hmac.compare_digest(supplied, owner.token):
                    self.reply(401, {'error': 'Private Hepta operator credential required'})
                    return False
                expected = '127.0.0.1:' + str(owner.port)
                if self.headers.get('Host') not in (expected, 'localhost:' + str(owner.port)):
                    self.reply(403, {'error': 'Invalid loopback Host'})
                    return False
                origin = self.headers.get('Origin')
                if origin is not None and origin not in ('http://' + expected, 'http://localhost:' + str(owner.port)):
                    self.reply(403, {'error': 'Origin not allowed'})
                    return False
                return True

            def do_GET(self):
                if self.path == '/health':
                    self.reply(200, {'ready': not owner.engine._closing and not owner.engine._admission_paused,
                        'tools': len(owner.engine.registry.tools()),
                        'implemented': len(owner.engine.registry.implemented_tools),
                        'active': len(owner.engine.tasks), 'provider': 'Hepta Runtime',
                        'admission_paused': owner.engine._admission_paused})
                elif self.path == '/mcp':
                    if self.authenticated():
                        self.reply(405, {'error': 'Use JSON POST; this server has no notification SSE stream'})
                else:
                    self.reply(404)

            def do_DELETE(self):
                if self.path != '/mcp':
                    self.reply(404); return
                if not self.authenticated():
                    return
                identity = self.headers.get('Mcp-Session-Id')
                with owner.sessions_lock:
                    found = owner.sessions.pop(identity, None)
                self.reply(200 if found else 404)

            def do_POST(self):
                if self.path not in ('/mcp', '/maintenance'):
                    self.reply(404); return
                if not self.authenticated():
                    self.close_connection = True
                    return
                if self.headers.get('Content-Type', '').split(';', 1)[0] != 'application/json':
                    self.reply(415); self.close_connection = True; return
                try:
                    length = int(self.headers.get('Content-Length', '-1'))
                    if not 0 <= length <= owner.maximum_request:
                        self.reply(413); self.close_connection = True; return
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise ValueError('incomplete message')
                    request = strict_json(raw)
                except (ValueError, UnicodeError, TimeoutError):
                    self.reply(400, {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Invalid JSON request'}})
                    return
                if not isinstance(request, dict):
                    self.reply(400); return
                if self.path == '/maintenance':
                    # Dispatch on the same event loop as engine.call. Setting
                    # the fence and beginning a new effect cannot interleave.
                    status, value = asyncio.run_coroutine_threadsafe(owner.maintenance(request), owner.loop).result(timeout=5)
                    self.reply(status, value)
                    return
                identity = self.headers.get('Mcp-Session-Id')
                method = request.get('method')
                if method == 'initialize':
                    params = request.get('params', {})
                    if not isinstance(params, dict):
                        self.reply(400, {'jsonrpc': '2.0', 'id': request.get('id'),
                            'error': {'code': -32602, 'message': 'Object parameters required'}})
                        return
                    requested = params.get('protocolVersion', '2025-06-18')
                    if requested not in VERSIONS:
                        self.reply(400, {'jsonrpc': '2.0', 'id': request.get('id'),
                            'error': {'code': -32022, 'message': 'Use the supported legacy MCP transport through the Hepta facade'}})
                        return
                    identity = secrets.token_hex(32)
                    session = JournalSession(owner.engine, identity)
                    with owner.sessions_lock:
                        # Expired connections lose protocol state only; durable
                        # call IDs and original results remain in the journal.
                        stale = [k for k, v in owner.sessions.items() if time.monotonic() - v.last_seen > 86400]
                        for key in stale:
                            del owner.sessions[key]
                        owner.sessions[identity] = session
                else:
                    with owner.sessions_lock:
                        session = owner.sessions.get(identity)
                    if session is None:
                        self.reply(404, raw=b'Not Found: Session not found')
                        return
                    version = self.headers.get('MCP-Protocol-Version')
                    if version is not None and version not in VERSIONS:
                        self.reply(400); return
                try:
                    future = asyncio.run_coroutine_threadsafe(session.dispatch(request), owner.loop)
                    response = future.result(timeout=30)
                except Exception:
                    # The owner task is deliberately not cancelled here: an
                    # HTTP timeout never proves that an effect did not occur.
                    self.reply(500, {'jsonrpc': '2.0', 'id': request.get('id'),
                        'error': {'code': -32603, 'message': 'Operation outcome unavailable; do not replay automatically'}})
                    return
                if response is None:
                    self.reply(202, session=identity)
                else:
                    self.reply(200, response, session=identity)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.http_thread = threading.Thread(target=self.server.serve_forever, name='hepta-computer-http', daemon=True)
        self.http_thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def maintenance(self, request):
        action = request.get('action')
        if action == 'pause' and set(request) == {'action'}:
            if self.engine._closing or self.maintenance_lease is not None:
                return 409, {'error': 'Owner is already closing or paused'}
            self.engine._admission_paused = True
            self.maintenance_lease = secrets.token_hex(32)
            return 200, {'admission_paused': True, 'lease': self.maintenance_lease,
                'active': len(self.engine.tasks)}
        if action == 'resume' and set(request) == {'action', 'lease'}:
            supplied = request['lease']
            if (not isinstance(supplied, str) or not supplied.isascii() or self.maintenance_lease is None
                    or not hmac.compare_digest(supplied, self.maintenance_lease) or self.engine._closing):
                return 409, {'error': 'Matching maintenance lease required'}
            self.maintenance_lease = None
            self.engine._admission_paused = False
            return 200, {'admission_paused': False}
        return 400, {'error': 'Explicit pause or matching-lease resume required'}

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        # Do not release the sole-owner journal lock while a cancelled wrapper
        # still has a live worker thread performing an accepted OS action.
        try:
            asyncio.run_coroutine_threadsafe(self.engine.close(), self.loop).result()
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.loop_thread.join(3)
            self.http_thread.join(3)
            self.loop.close()
