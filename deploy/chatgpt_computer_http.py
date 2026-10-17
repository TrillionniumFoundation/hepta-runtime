#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Authenticated loopback MCP HTTP facade for the unchanged 110-tool composition.

HTTP workers dispatch directly: no stdio queue and no shared pipe lifecycle.
Legacy sessions own independent proxy/ID tables. Stateless modern HTTP requests
lease independent reusable proxy lanes, which grow with OS-admitted concurrency.
No caller request is retried. Termination drains existing calls without replay.
"""
from __future__ import annotations

import argparse
import hmac
import http.server
import json
import pathlib
import secrets
import signal
import socket
import threading

from chatgpt_computer_operator import add_proxy_arguments, build_proxy
from chatgpt_full_operator import (MAX_REQUEST, MAX_RESPONSE, canonical, error,
                                  private_token, request_era, valid_request)


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate_json_key')
        value[key] = item
    return value


def _parse(raw):
    def invalid(_):
        raise ValueError('invalid_json_number')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=invalid)


def unlimited_proxy(proxy):
    """Only HTTP instances bypass the stdio compatibility admission budget."""
    seen, pending = set(), [proxy]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        current.active_request_limit = None
        pending.extend(child for name in ('native', 'compatibility', 'legacy', 'predecessor')
                       if (child := getattr(current, name, None)) is not None)
    return proxy


class _Session:
    def __init__(self, proxy, sid=None):
        self.proxy, self.sid = proxy, sid
        self.users = 0
        self.deleted = False
        self.registered = False
        self.protocol = None


class SessionNotFound(LookupError):
    pass


class ServerClosing(RuntimeError):
    pass


class ComputerHTTPServer(http.server.ThreadingHTTPServer):
    # shutdown stops admission; server_close then waits for existing handlers.
    # Native waits retain their existing bounded 38/150-second timeouts, and
    # idle/write sockets have a 30-second timeout. No active effect is replayed.
    daemon_threads = False
    block_on_close = True
    # Permit restart after closed connections enter TIME_WAIT; a live listener
    # remains exclusive because SO_REUSEPORT stays disabled.
    allow_reuse_address = True
    request_queue_size = socket.SOMAXCONN

    def __init__(self, address, proxy_factory, auth_token):
        if (address[0] != '127.0.0.1' or not isinstance(auth_token, str)
                or not 0 < len(auth_token) <= 4096
                or any(not 33 <= ord(char) <= 126 for char in auth_token)):
            raise ValueError('explicit_loopback_and_private_token_required')
        self._factory = proxy_factory
        self._token = auth_token
        self._lock = threading.RLock()
        # Read-only job-page cursors belong to this HTTP service, not to one
        # stateless modern proxy lane. Effect owners, credentials, workdirs and
        # native sessions remain independent for every lane.
        self._shared_readonly_registry_pager = None
        self._sessions = {}
        self._modern_idle = []
        self._modern_busy = {}
        self._closing = False
        self._stats = {'active_requests': 0, 'requests_started': 0,
                       'dispatches_completed': 0, 'responses_written': 0,
                       'response_delivery_failures': 0}
        seed = self._new_proxy()
        self.contract = seed.contract
        self._modern_idle.append(_Session(seed))
        try:
            super().__init__(address, ComputerHTTPHandler)
        except BaseException:
            seed.close(timeout=0)
            raise

    def _new_proxy(self):
        proxy = unlimited_proxy(self._factory())
        native = getattr(proxy, 'native', proxy)
        pager = getattr(native, 'registry_pager', None)
        if pager is None:
            return proxy
        try:
            with self._lock:
                existing = self._shared_readonly_registry_pager
                if existing is None:
                    self._shared_readonly_registry_pager = pager
                elif (type(existing) is not type(pager)
                      or existing.roots != pager.roots):
                    raise ValueError('readonly_registry_pager_root_mismatch')
                else:
                    # The pager has its own RLock, MAC key and strictly bounded
                    # frozen projections. Never share the upstream native
                    # session, effect registry, undo state or credentials.
                    native.registry_pager = existing
        except BaseException:
            proxy.close(timeout=0)
            raise
        return proxy

    def acquire(self, sid, *, legacy_initialize=False):
        with self._lock:
            if self._closing:
                raise ServerClosing('server_closing')
            if sid is not None:
                session = self._sessions.get(sid)
                if session is None or session.deleted:
                    raise SessionNotFound('session_not_found')
                session.users += 1
                return session
            if not legacy_initialize and self._modern_idle:
                session = self._modern_idle.pop()
                session.users = 1
                return session
        # Construct independent lanes outside the registry lock. OS thread and
        # file resources determine admission; no fixed request-count ceiling.
        session = _Session(self._new_proxy(), secrets.token_hex(32) if legacy_initialize else None)
        session.users = 1
        with self._lock:
            if self._closing:
                session.proxy.close(timeout=0)
                raise ServerClosing('server_closing')
        return session

    def register(self, session):
        with self._lock:
            if self._closing or session.sid is None or session.sid in self._sessions:
                raise ServerClosing('session_registration_refused')
            self._sessions[session.sid] = session
            session.registered = True

    def abort_registration(self, session):
        with self._lock:
            if self._sessions.get(session.sid) is session:
                self._sessions.pop(session.sid)
            session.deleted = True

    def release(self, session):
        close = False
        with self._lock:
            session.users -= 1
            if session.users == 0:
                if (session.deleted or self._closing
                        or session.sid is not None and not session.registered):
                    close = True
                elif session.sid is None:
                    self._modern_idle.append(session)
        if close:
            session.proxy.close(timeout=0)

    def delete(self, sid):
        with self._lock:
            session = self._sessions.pop(sid, None)
            if session is None:
                raise SessionNotFound('session_not_found')
            session.deleted = True
            close = session.users == 0
        if close:
            session.proxy.close(timeout=0)

    def track_modern(self, session, context):
        key = secrets.token_hex(24)
        with self._lock:
            self._modern_busy[key] = (session, context)
        return key

    def untrack_modern(self, key):
        with self._lock:
            self._modern_busy.pop(key, None)

    def note_started(self):
        with self._lock:
            self._stats['active_requests'] += 1
            self._stats['requests_started'] += 1

    def note_completed(self):
        with self._lock:
            self._stats['dispatches_completed'] += 1

    def note_finished(self, written):
        with self._lock:
            self._stats['active_requests'] -= 1
            self._stats['responses_written' if written else 'response_delivery_failures'] += 1

    def status(self):
        with self._lock:
            return {'schema': 'hepta-computer-http-status-v1', **self._stats,
                    'closing': self._closing, 'legacy_sessions': len(self._sessions),
                    'modern_idle_lanes': len(self._modern_idle),
                    'modern_busy_lanes': len(self._modern_busy)}

    def server_close(self):
        with self._lock:
            self._closing = True
            all_sessions = (list(self._sessions.values()) + self._modern_idle
                            + [session for session, _ in self._modern_busy.values()])
            sessions = list({id(session): session for session in all_sessions}.values())
            self._sessions.clear()
            self._modern_idle = []
            for session in sessions:
                session.deleted = True
        for session in sessions:
            if session.users == 0:
                session.proxy.close(timeout=0)
        super().server_close()


class ComputerHTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'HeptaMCP'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, *_):
        # Requests, session IDs, headers and tool arguments never enter logs.
        return

    def _reply(self, status, value=None, *, sid=None, plain=None):
        payload = plain if plain is not None else (b'' if value is None else canonical(value))
        if len(payload) > MAX_RESPONSE:
            ident = value.get('id') if isinstance(value, dict) else None
            status, payload = 500, canonical(error(ident, -32603, 'HTTP response exceeds facade limit',
                                                  outcome='unknown', automatic_retry=False))
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain; charset=utf-8' if plain is not None else 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if sid is not None:
            self.send_header('Mcp-Session-Id', sid)
        self.end_headers()
        if payload:
            self.wfile.write(payload)
        self.wfile.flush()
        self._response_written = True

    def _authorize(self):
        values = self.headers.get_all('X-Hepta-Runtime-Token', [])
        try:
            authenticated = len(values) == 1 and hmac.compare_digest(
                values[0].encode('ascii'), self.server._token.encode('ascii'))
        except UnicodeError:
            authenticated = False
        if not authenticated:
            self.close_connection = True
            self._reply(401, {'error': 'Unauthorized'})
            return False
        origins = self.headers.get_all('Origin', [])
        if origins:
            expected = 'http://127.0.0.1:' + str(self.server.server_port)
            if len(origins) != 1 or origins[0] != expected:
                self.close_connection = True
                self._reply(403, {'error': 'Origin refused'})
                return False
        if self.path not in ('/mcp', '/health'):
            self.close_connection = True
            self._reply(404, {'error': 'Not found'})
            return False
        return True

    def _sid(self):
        values = self.headers.get_all('Mcp-Session-Id', [])
        if len(values) > 1 or values and (len(values[0]) != 64
                                         or any(char not in '0123456789abcdef' for char in values[0])):
            raise ValueError('invalid_http_session')
        return values[0] if values else None

    def do_POST(self):
        if not self._authorize():
            return
        session = context = modern_key = None
        self._response_written = False
        method = None
        try:
            if self.path != '/mcp':
                self._reply(405, {'error': 'Method not allowed'})
                return
            if self.headers.get_all('Transfer-Encoding'):
                raise ValueError('transfer_encoding_refused')
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
                raise ValueError('content_length_required')
            length = int(lengths[0])
            if not 0 < length <= MAX_REQUEST:
                self.close_connection = True
                self._reply(413, {'error': 'Request size refused'})
                return
            content_type = self.headers.get_content_type()
            if content_type != 'application/json':
                self.close_connection = True
                self._reply(415, {'error': 'JSON required'})
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('incomplete_http_body')
            request = _parse(raw)
            invalid = valid_request(request, self.server.contract)
            if invalid is not None:
                self._reply(200, invalid)
                return
            sid = self._sid()
            method = request['method']
            notification = method.startswith('notifications/')
            era, _ = request_era(request)
            if sid is None and era == 'legacy' and method != 'initialize':
                self._reply(400, error(request.get('id'), -32071, 'Legacy HTTP session required',
                                       outcome='not_submitted', automatic_retry=False))
                return
            if sid is not None and method == 'initialize':
                self._reply(400, error(request.get('id'), -32600, 'Initialize requires a new HTTP session'))
                return
            if sid is None and notification:
                if method == 'notifications/cancelled':
                    # Even a currently unique ID might be a newer reuse of an
                    # old lifecycle. Missing session/generation is not authority
                    # to cancel that call. Explicit durable tool-cancel routes
                    # remain available with their original owner checks.
                    self._reply(400, {'error': 'Cancellation requires an HTTP session identity'})
                    return
                self._reply(202)
                return
            session = self.server.acquire(sid, legacy_initialize=(method == 'initialize'))
            versions = self.headers.get_all('MCP-Protocol-Version', [])
            if len(versions) > 1 or (era == 'legacy' and session.protocol is not None
                                    and versions and versions[0] != session.protocol):
                raise ValueError('http_protocol_version_mismatch')
            if notification:
                session.proxy.dispatch(request)
                self._reply(202)
                return
            context, refused = session.proxy._reserve(request, remember=True)
            if refused is not None:
                self._reply(200, refused)
                return
            self.server.note_started()
            if session.sid is None:
                modern_key = self.server.track_modern(session, context)
            response = session.proxy.dispatch(request, context)
            self.server.note_completed()
            initialized = (method == 'initialize' and isinstance(response, dict)
                           and 'result' in response)
            if initialized:
                session.protocol = response['result'].get('protocolVersion')
                self.server.register(session)
            elif method == 'initialize':
                session.deleted = True
            # Keep reservation through the actual synchronous response write.
            self._reply(200, response, sid=session.sid if initialized else None)
        except SessionNotFound:
            self.close_connection = True
            self._reply(404, plain=b'Not Found: Session not found')
        except ServerClosing:
            self.close_connection = True
            self._reply(503, error(request.get('id') if isinstance(locals().get('request'), dict) else None,
                -32603, 'HTTP facade admission is closing',
                outcome='unknown' if context is not None else 'not_submitted', automatic_retry=False))
        except (ValueError, UnicodeError, RecursionError, OverflowError):
            self.close_connection = True
            if context is None:
                self._reply(400, error(None, -32700, 'Invalid bounded MCP HTTP request'))
            else:
                self._reply(500, error(context.ident, -32603,
                    'HTTP operation result unavailable; do not replay a write blindly',
                    outcome='unknown', automatic_retry=False))
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            self.close_connection = True
        except Exception:
            self.close_connection = True
            self._reply(500, error(request.get('id') if isinstance(locals().get('request'), dict) else None,
                                   -32603, 'HTTP operation result unavailable; do not replay a write blindly',
                                   outcome='unknown' if context is not None else 'not_submitted',
                                   automatic_retry=False))
        finally:
            if modern_key is not None:
                self.server.untrack_modern(modern_key)
            if context is not None:
                session.proxy._finish(context)
                self.server.note_finished(self._response_written)
            if session is not None:
                if method == 'initialize' and not self._response_written:
                    self.server.abort_registration(session)
                self.server.release(session)

    def do_DELETE(self):
        if not self._authorize():
            return
        try:
            if self.path != '/mcp':
                self._reply(405, {'error': 'Method not allowed'})
                return
            sid = self._sid()
            if sid is None:
                raise ValueError('session_required')
            self.server.delete(sid)
            self._reply(200)
        except SessionNotFound:
            self._reply(404, plain=b'Not Found: Session not found')
        except ValueError:
            self._reply(400, {'error': 'HTTP session required'})

    def do_GET(self):
        if self._authorize():
            if self.path == '/health':
                self._reply(200, self.server.status())
                return
            self.send_response(405)
            self.send_header('Allow', 'POST, DELETE')
            self.send_header('Content-Length', '0')
            self.end_headers()


def serve(server):
    """Main-thread signal lifecycle: stop admission, then join existing handlers."""
    def stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()
    previous = {item: signal.signal(item, stop) for item in (signal.SIGTERM, signal.SIGINT)}
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
        for item, handler in previous.items():
            signal.signal(item, handler)


def main():
    parser = add_proxy_arguments(argparse.ArgumentParser(description=__doc__))
    parser.add_argument('--bind', default='127.0.0.1:8795')
    parser.add_argument('--auth-token-file', required=True, type=pathlib.Path)
    args = parser.parse_args()
    host, separator, port = args.bind.rpartition(':')
    if separator != ':' or host != '127.0.0.1' or not port.isdigit():
        parser.error('bind must be explicit IPv4 loopback host:port')
    server = ComputerHTTPServer((host, int(port)), lambda: build_proxy(args),
                                private_token(args.auth_token_file))
    serve(server)


if __name__ == '__main__':
    main()
