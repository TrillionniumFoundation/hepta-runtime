# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Durable full tool results and argument history, without lifetime slot eviction."""
from __future__ import annotations
import base64
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import sqlite3
import stat
import threading
import time
import uuid
from .processes import _private_root
from .registry import ToolError


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


class CallJournal:
    def __init__(self, state_dir):
        self.state_dir = pathlib.Path(state_dir)
        directory = _private_root(self.state_dir)
        try:
            previous_owner = 'owner.lock' in os.listdir(directory)
            self.owner_fd = os.open('owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            info = os.fstat(self.owner_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                os.close(self.owner_fd)
                self.owner_fd = None
                raise ToolError('unsafe call journal owner lock')
            try:
                fcntl.flock(self.owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BaseException:
                os.close(self.owner_fd)
                self.owner_fd = None
                raise
            if previous_owner and 'calls.sqlite3' not in os.listdir(directory):
                raise ToolError('Existing call journal is missing calls.sqlite3; restore it before starting')
            for name in ('calls.sqlite3', 'calls.sqlite3-wal', 'calls.sqlite3-shm'):
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                    raise ToolError('unsafe call journal member')
            descriptor = os.open('calls.sqlite3', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            os.close(descriptor)
            self.connection = sqlite3.connect(self.state_dir / 'calls.sqlite3', check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self.lock = threading.RLock()
            if previous_owner:
                tables = {row[0] for row in self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {'calls', 'clients'} <= tables:
                    raise ToolError('Existing call journal schema is missing; restore the original database')
            with self.connection:
                self.connection.execute('PRAGMA journal_mode=WAL')
                self.connection.execute('PRAGMA synchronous=FULL')
                self.connection.execute('CREATE TABLE IF NOT EXISTS calls (call_id TEXT PRIMARY KEY, rpc_key TEXT UNIQUE, tool TEXT NOT NULL, arguments BLOB NOT NULL, state TEXT NOT NULL, started REAL NOT NULL, finished REAL, result BLOB, digest TEXT, background INTEGER NOT NULL DEFAULT 0)')
                self.connection.execute('CREATE INDEX IF NOT EXISTS calls_started ON calls(started)')
                self.connection.execute('CREATE TABLE IF NOT EXISTS clients (client BLOB PRIMARY KEY, first_seen REAL NOT NULL, last_seen REAL NOT NULL)')
                self.connection.execute("UPDATE calls SET state='unknown' WHERE state IN ('accepted','executing')")
            for name in ('calls.sqlite3', 'calls.sqlite3-wal', 'calls.sqlite3-shm'):
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise ToolError('unsafe call journal member after initialization')
                os.chmod(name, 0o600, dir_fd=directory, follow_symlinks=False)
        except BaseException:
            if getattr(self, 'connection', None) is not None:
                self.connection.close()
            if getattr(self, 'owner_fd', None) is not None:
                os.close(self.owner_fd)
                self.owner_fd = None
            raise
        finally:
            os.close(directory)

    def begin(self, tool, arguments, rpc_key):
        raw = encode(arguments)
        with self.lock, self.connection:
            old = self.connection.execute('SELECT * FROM calls WHERE rpc_key=?', (rpc_key,)).fetchone()
            if old is not None:
                if old['tool'] != tool or old['arguments'] != raw:
                    raise ToolError('Request identity is already bound to different arguments; no dispatch')
                return dict(old), True
            identity = 'hepta-call-' + uuid.uuid4().hex
            self.connection.execute('INSERT INTO calls(call_id,rpc_key,tool,arguments,state,started) VALUES(?,?,?,?,?,?)',
                                    (identity, rpc_key, tool, raw, 'accepted', time.time()))
            return self.lookup(identity), False

    def executing(self, identity):
        with self.lock, self.connection:
            self.connection.execute("UPDATE calls SET state='executing' WHERE call_id=? AND state='accepted'", (identity,))

    def mark_background(self, identity):
        with self.lock, self.connection:
            self.connection.execute('UPDATE calls SET background=1 WHERE call_id=?', (identity,))

    def complete(self, identity, result):
        raw = encode(result)
        with self.lock, self.connection:
            self.connection.execute('UPDATE calls SET state=?,finished=?,result=?,digest=? WHERE call_id=? AND state IN (\'accepted\',\'executing\')',
                ('failed' if result.get('isError') is True else 'completed', time.time(), raw, hashlib.sha256(raw).hexdigest(), identity))

    def lookup(self, identity):
        with self.lock:
            row = self.connection.execute('SELECT * FROM calls WHERE call_id=?', (identity,)).fetchone()
        if row is None:
            raise ToolError('No retained tool call with this call_id')
        return dict(row)

    def result(self, identity):
        row = self.lookup(identity)
        result = {'call_id': identity, 'status': row['state'], 'tool': row['tool'],
                  'automatic_retry': False, 'provider': 'Hepta Runtime'}
        if row['result'] is not None:
            if hashlib.sha256(row['result']).hexdigest() != row['digest']:
                raise ToolError('Retained result integrity failure; no replay')
            result.update(result_sha256=row['digest'], result_bytes=len(row['result']))
            if len(row['result']) <= 2 * 1024 * 1024:
                result['result'] = json.loads(row['result'])
            else:
                result['result_reference'] = {'tool': 'hepta_call_result_page', 'call_id': identity,
                    'reason': 'Original result exceeds a direct wire response; read complete independent byte pages'}
        elif row['state'] == 'unknown':
            result['reason'] = 'Controller stopped before a confirmed result; original action is never replayed automatically'
        return result

    def page(self, identity, offset=0, limit=16384):
        row = self.lookup(identity)
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 1048576:
            raise ToolError('Invalid original result byte page')
        raw = row['result']
        if raw is None or hashlib.sha256(raw).hexdigest() != row['digest']:
            raise ToolError('Original result unavailable; no replay')
        following = min(len(raw), offset + limit)
        if offset > len(raw):
            raise ToolError('Result byte offset exceeds original length')
        return {'call_id': identity, 'offset': offset, 'next_offset': following, 'eof': following == len(raw),
                'total_bytes': len(raw), 'sha256': row['digest'],
                'data_base64': base64.b64encode(raw[offset:following]).decode(), 'immutable_original_bytes': True}

    def recent(self, maximum=50, tool=None, since=None):
        if type(maximum) is not int or not 1 <= maximum <= 1000:
            raise ToolError('maxResults must be an integer from 1 to 1000')
        conditions, values = ["tool NOT IN ('get_recent_tool_calls','get_tool_result','list_remote_tool_calls','hepta_call_result_page')"], []
        if tool is not None:
            conditions.append('tool=?'); values.append(tool)
        if since is not None:
            try:
                stamp = datetime.datetime.fromisoformat(since.replace('Z', '+00:00')).timestamp()
            except (AttributeError, ValueError, OverflowError) as exc:
                raise ToolError('since must be an ISO date-time') from exc
            conditions.append('started>=?'); values.append(stamp)
        with self.lock:
            rows = self.connection.execute('SELECT * FROM calls WHERE ' + ' AND '.join(conditions) + ' ORDER BY started DESC LIMIT ?', values + [maximum]).fetchall()
        result = []
        for row in reversed(rows):
            if row['result'] is not None and hashlib.sha256(row['result']).hexdigest() != row['digest']:
                raise ToolError('Retained history result integrity failure; no partial history returned')
            result.append({'timestamp': datetime.datetime.fromtimestamp(row['started']).astimezone().isoformat(),
                'toolName': row['tool'], 'args': json.loads(row['arguments']),
                'output': None if row['result'] is None else json.loads(row['result']) if len(row['result']) <= 4096
                          else {'omitted': True, 'original_bytes': len(row['result']),
                                'read_original_with': 'hepta_call_result_page', 'call_id': row['call_id']},
                'success': row['state'] == 'completed', 'status': row['state'], 'call_id': row['call_id'],
                'duration': None if row['finished'] is None else round((row['finished'] - row['started']) * 1000)})
        return result

    def background(self, limit=50):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ToolError('limit must be from 1 to 1000')
        with self.lock:
            rows = self.connection.execute('SELECT call_id,tool,state,started,finished FROM calls WHERE background=1 ORDER BY started DESC LIMIT ?', (limit,)).fetchall()
        return [dict(row) for row in rows]

    def stats(self):
        with self.lock:
            rows = self.connection.execute('SELECT tool,state,COUNT(*) AS count,MIN(started) AS first,MAX(started) AS last,AVG((finished-started)*1000) AS elapsed FROM calls GROUP BY tool,state').fetchall()
        counts, completed, failed, unknown, active = {}, 0, 0, 0, 0
        for row in rows:
            counts[row['tool']] = counts.get(row['tool'], 0) + row['count']
            if row['state'] == 'completed': completed += row['count']
            elif row['state'] == 'failed': failed += row['count']
            elif row['state'] == 'unknown': unknown += row['count']
            else: active += row['count']
        return {'provider': 'Hepta Runtime', 'totalToolCalls': sum(counts.values()), 'successfulCalls': completed,
                'failedCalls': failed, 'unknownCalls': unknown, 'activeCalls': active, 'toolCounts': counts,
                'firstUsed': min((row['first'] for row in rows), default=None),
                'lastUsed': max((row['last'] for row in rows), default=None),
                'historyRetention': 'original arguments and full results retained until explicit administrator maintenance',
                'fixedLifetimeSlotLimit': None, 'dcHistoricalStatisticsImported': False}

    def observe_client(self, client):
        raw = encode(client)
        with self.lock, self.connection:
            self.connection.execute('INSERT INTO clients(client,first_seen,last_seen) VALUES(?,?,?) ON CONFLICT(client) DO UPDATE SET last_seen=excluded.last_seen', (raw, time.time(), time.time()))

    def clients(self):
        with self.lock:
            rows = self.connection.execute('SELECT * FROM clients ORDER BY first_seen').fetchall()
        return [dict(json.loads(row['client']), firstSeen=row['first_seen'], lastSeen=row['last_seen']) for row in rows]

    def close(self):
        with self.lock:
            if self.owner_fd is not None:
                self.connection.close()
                os.close(self.owner_fd)
                self.owner_fd = None
