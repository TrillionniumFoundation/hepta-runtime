# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent DC 0.2.52 search semantics on real ripgrep and private journals.

No search is relaunched from a journal. Results have no implicit row, byte, or
time ceiling: maxResults=0 and timeout_ms=0 retain their original rg semantics.
"""
from __future__ import annotations
import asyncio
import codecs
import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
import uuid
import zipfile
import xml.etree.ElementTree as ET
from .registry import ToolError, text_result

TOOL_NAMES = frozenset({'start_search', 'get_more_search_results', 'stop_search', 'list_searches'})
SESSION_ID = re.compile(r'search_([0-9]+)_([0-9]+)')


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private(info, directory=False):
    if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise ToolError('unsafe private search journal')


def _root(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ToolError('search state must be an absolute private directory')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = following
        _private(os.fstat(fd), True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        _private(before)
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        if _stamp(before) != _stamp(os.fstat(fd)):
            raise ToolError('search journal changed during read')
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if _stamp(before) != _stamp(named):
            raise ToolError('search journal member replaced during read')
        return b''.join(chunks)
    finally:
        os.close(fd)


def _publish(directory, value, *, initial=False):
    try:
        existing = os.stat('metadata.json', dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        if not initial:
            raise ToolError('search metadata disappeared; never recreate old history')
    else:
        _private(existing)
        if initial:
            raise ToolError('search metadata already exists; never rebind an identity')
    name = '.tmp-' + uuid.uuid4().hex
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, 'metadata.json', src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass


def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ToolError(name + ' must be a finite number')
    return value


def _js_number(value):
    if value == 0:
        return '0'
    if int(value) == value and abs(value) < 1e21:
        return str(int(value))
    text = str(value)
    if 'e' in text:
        mantissa, exponent = text.split('e')
        exponent = int(exponent)
        if -6 <= exponent < 21:
            from decimal import Decimal
            return format(Decimal(text), 'f').rstrip('0').rstrip('.') if '.' in format(Decimal(text), 'f') else format(Decimal(text), 'f')
        return mantissa.rstrip('0').rstrip('.') + 'e' + ('+' if exponent >= 0 else '-') + str(abs(exponent))
    return text


def _excel_date(value, date_1904):
    # ExcelJS projects date cells as native JS Date objects. String(Date)
    # describes the machine's local timezone rather than the workbook format.
    milliseconds = round((float(value) - 25569 + (1462 if date_1904 else 0)) * 86400000)
    date = datetime.datetime.fromtimestamp(milliseconds / 1000, datetime.timezone.utc).astimezone()
    weekdays = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
    months = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
    zone = date.tzname() or ''
    zone = {'UTC': 'Coordinated Universal Time', 'GMT': 'Coordinated Universal Time',
            'EST': 'Eastern Standard Time', 'EDT': 'Eastern Daylight Time',
            'CST': 'Central Standard Time', 'CDT': 'Central Daylight Time',
            'MST': 'Mountain Standard Time', 'MDT': 'Mountain Daylight Time',
            'PST': 'Pacific Standard Time', 'PDT': 'Pacific Daylight Time'}.get(zone, zone)
    return f'{weekdays[date.weekday()]} {months[date.month - 1]} {date.day:02d} {date.year:04d} {date:%H:%M:%S} GMT{date:%z} ({zone})'


def _exact(pattern):
    return bool(re.search(r'\.[a-zA-Z0-9]+$', pattern)) and not any(c in pattern for c in '*?[]{}')


def build_rg_args(options):
    """Keep official argument ordering, including file-pattern re-inclusion."""
    content = options['searchType'] == 'content'
    args = ['--json', '--line-number'] if content else ['--files']
    if content and options['literalSearch']:
        args.append('-F')
    if content and options['contextLines'] > 0:
        args.extend(['-C', _js_number(options['contextLines'])])
    if content and options['ignoreCase']:
        args.append('-i')
    if options['includeHidden']:
        args.append('--hidden')
    if options.get('maxResults', 0) > 0:
        args.extend(['-m', _js_number(options['maxResults'])])
    glob = '--iglob' if options['ignoreCase'] else '--glob'
    for pattern in options.get('filePattern', '').split('|'):
        if pattern.strip():
            args.extend(['-g' if content else glob, pattern.strip()])
    if content:
        args.extend(['--', options['pattern'], options['rootPath']])
    else:
        pattern = options['pattern']
        if not _exact(pattern) and not any(c in pattern for c in '*?[]{}'):
            pattern = '*' + pattern + '*'
        args.extend([glob, pattern, options['rootPath']])
    return args


def parse_rg_line(line, search_type):
    if not line.strip():
        return None
    if search_type == 'files':
        return {'file': line.strip(), 'type': 'file'}, False
    try:
        parsed = json.loads(line)
        data = parsed.get('data', {})
        if parsed.get('type') == 'match':
            matches = data.get('submatches', [])
            first = matches[0].get('match', {}).get('text') if matches else None
            return {'file': data['path'].get('text'), 'line': data['line_number'],
                    'match': first or data['lines'].get('text'), 'type': 'content'}, False
        if parsed.get('type') == 'context':
            return {'file': data['path'].get('text'), 'line': data['line_number'],
                    'match': data['lines'].get('text', '').strip(), 'type': 'content'}, True
    except (ValueError, KeyError, TypeError):
        pass
    return None


class _Session:
    def __init__(self, directory, metadata):
        self.directory, self.metadata = directory, metadata
        self.rows = []
        self.process = self.thread = None
        self.lock = threading.RLock()
        self.first = threading.Event()
        self.cancel = threading.Event()
        self.timer = self.early_timer = None
        self.failure = None
        self.hasher = hashlib.sha256()


class SearchManager:
    tool_names = TOOL_NAMES

    def __init__(self, state_dir, config):
        self.config = config
        self.state_dir = Path(state_dir)
        self.directory = _root(self.state_dir)
        self.owner = None
        try:
            self.owner = os.open('manager.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
            _private(os.fstat(self.owner))
            fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            if self.owner is not None:
                os.close(self.owner)
            os.close(self.directory)
            raise
        self.sessions, self.counter = {}, 0
        self.lock, self.closed = threading.RLock(), False
        try:
            self._load()
        except BaseException:
            for session in self.sessions.values():
                os.close(session.directory)
            os.close(self.owner)
            os.close(self.directory)
            raise

    def _load(self):
        for name in sorted(os.listdir(self.directory)):
            if name == 'manager.lock':
                continue
            match = SESSION_ID.fullmatch(name)
            if not match:
                raise ToolError('unexpected search journal member')
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.directory)
            try:
                _private(os.fstat(fd), True)
                value = json.loads(_read(fd, 'metadata.json'))
                if value.get('id') != name or value.get('schema') != 1:
                    raise ToolError('search journal identity mismatch')
                session = _Session(fd, value)
                raw = _read(fd, 'results.ndjson')
                committed = value['committedBytes']
                if type(committed) is not int or not 0 <= committed <= len(raw):
                    raise ToolError('search journal committed prefix is unavailable')
                prefix = raw[:committed]
                if prefix and not prefix.endswith(b'\n'):
                    raise ToolError('search journal committed row is incomplete')
                session.hasher.update(prefix)
                if session.hasher.hexdigest() != value.get('committedSha256'):
                    raise ToolError('search journal committed prefix digest changed')
                session.rows = [json.loads(line) for line in prefix.splitlines()]
                if len(session.rows) != value['totalMatches'] + value['totalContextLines']:
                    raise ToolError('search journal row count changed')
                if not value['isComplete']:
                    session.metadata.update(isComplete=True, wasIncomplete=True, interrupted=True,
                                            finishedTime=value.get('lastUpdateTime', value['startTime']))
                    _publish(fd, session.metadata)
                self.sessions[name] = session
                self.counter = max(self.counter, int(match.group(1)))
            except BaseException:
                os.close(fd)
                raise

    def _options(self, args):
        for key in ('path', 'pattern'):
            if not isinstance(args.get(key), str):
                raise ToolError(key + ' must be a string')
        resolver = getattr(self.config, 'resolve_path', None)
        path = resolver(args['path']) if resolver else Path(args['path']).expanduser().resolve(strict=True)
        options = {'rootPath': str(path), 'pattern': args['pattern'],
                   'searchType': args.get('searchType', 'files'), 'filePattern': args.get('filePattern', ''),
                   'ignoreCase': args.get('ignoreCase', True), 'includeHidden': args.get('includeHidden', False),
                   'contextLines': args.get('contextLines', 5), 'literalSearch': args.get('literalSearch', False),
                   'earlyTermination': args.get('earlyTermination', True)}
        if options['searchType'] not in ('files', 'content'):
            raise ToolError('invalid searchType')
        for key in ('ignoreCase', 'includeHidden', 'literalSearch', 'earlyTermination'):
            if type(options[key]) is not bool:
                raise ToolError(key + ' must be a boolean')
        if not isinstance(options['filePattern'], str):
            raise ToolError('filePattern must be a string')
        _number(options['contextLines'], 'contextLines')
        for key in ('maxResults', 'timeout_ms'):
            if key in args:
                options[key] = _number(args[key], key)
        return options

    def _start(self, args):
        options = self._options(args)
        with self.lock:
            if self.closed:
                raise ToolError('search manager is closed')
            self.counter += 1
            identity = f'search_{self.counter}_{int(time.time() * 1000)}'
            os.mkdir(identity, 0o700, dir_fd=self.directory)
            fd = os.open(identity, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.directory)
            log = os.open('results.ndjson', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            os.close(log)
            now = int(time.time() * 1000)
            value = {'schema': 1, 'id': identity, 'options': options, 'startTime': now, 'lastReadTime': now,
                     'isComplete': False, 'isError': False, 'error': '', 'totalMatches': 0,
                     'totalContextLines': 0, 'committedBytes': 0, 'lastUpdateTime': now,
                     'committedSha256': hashlib.sha256(b'').hexdigest()}
            session = _Session(fd, value)
            _publish(fd, value, initial=True)
            self.sessions[identity] = session
            try:
                session.process = subprocess.Popen(['/usr/bin/rg', *build_rg_args(options)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    cwd=getattr(self.config, 'workspace', None), start_new_session=True)
            except OSError as error:
                value.update(isComplete=True, isError=True, error='Process error: ' + str(error), finishedTime=now)
                _publish(fd, value)
                raise
            session.thread = threading.Thread(target=self._collect, args=(session,), daemon=True)
            session.thread.start()
            timeout = options.get('timeout_ms', 1500 if _exact(options['pattern']) else 0)
            if timeout:
                session.timer = threading.Timer(max(0.001, timeout / 1000), self._terminate, args=(session,))
                session.timer.daemon = True
                session.timer.start()
        session.first.wait(0.04)
        with session.lock:
            metadata = dict(session.metadata)
            rows = list(session.rows)
        output = (f'Started {"content search" if options["searchType"] == "content" else "file search"} session: {identity}\n'
                  f'Pattern: "{options["pattern"]}"\nPath: {args["path"]}\n'
                  f'Status: {"COMPLETED" if metadata["isComplete"] else "RUNNING"}\n'
                  f'Runtime: {self._runtime(metadata)}ms\nTotal results: {metadata["totalMatches"]}\n\n')
        if rows:
            output += 'Initial results:\n' + ''.join(self._format_row(row) for row in rows[:10])
            if len(rows) > 10:
                output += f'... and {len(rows) - 10} more results\n'
        output += '\n✅ Search completed.' if metadata['isComplete'] else '\n🔄 Search in progress. Use get_more_search_results to get more results.'
        return text_result(output)

    def _commit(self, session, rows):
        if not rows:
            return
        with session.lock:
            fd = os.open('results.ndjson', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=session.directory)
            try:
                before = os.fstat(fd)
                _private(before)
                if before.st_size != session.metadata['committedBytes']:
                    raise ToolError('search result journal changed outside its owner')
                raw = b''.join(json.dumps(row, ensure_ascii=False, separators=(',', ':')).encode() + b'\n' for row, _ in rows)
                view = memoryview(raw)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            for row, context in rows:
                session.rows.append(row)
                session.metadata['totalContextLines' if context else 'totalMatches'] += 1
            session.metadata['committedBytes'] += len(raw)
            session.hasher.update(raw)
            session.metadata['committedSha256'] = session.hasher.hexdigest()
            session.metadata['lastUpdateTime'] = int(time.time() * 1000)
            _publish(session.directory, session.metadata)

    def _consume(self, session, text):
        rows = []
        options = session.metadata['options']
        for line in text.splitlines():
            result = parse_rg_line(line, options['searchType'])
            if result is None:
                continue
            rows.append(result)
            if options['searchType'] == 'files' and options['earlyTermination'] and _exact(options['pattern']):
                filename, pattern = os.path.normpath(result[0]['file']), os.path.normpath(options['pattern'])
                if options['ignoreCase']:
                    filename, pattern = filename.lower(), pattern.lower()
                if filename.endswith(pattern):
                    if session.early_timer is None:
                        session.early_timer = threading.Timer(0.1, self._terminate, args=(session,))
                        session.early_timer.daemon = True
                        session.early_timer.start()
                    break
        self._commit(session, rows)

    def _collect(self, session):
        process = session.process
        selector = selectors.DefaultSelector()
        decoder = codecs.getincrementaldecoder('utf-8')('replace')
        buffer = ''
        try:
            selector.register(process.stdout, selectors.EVENT_READ, 'out')
            selector.register(process.stderr, selectors.EVENT_READ, 'err')
            while selector.get_map():
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == 'err':
                        with session.lock:
                            session.metadata['error'] += chunk.decode('utf-8', 'replace')
                    else:
                        buffer += decoder.decode(chunk)
                        lines, separator, buffer_tail = buffer.rpartition('\n')
                        if separator:
                            self._consume(session, lines)
                            buffer = buffer_tail
                        session.first.set()
            buffer += decoder.decode(b'', final=True)
            if buffer.strip():
                self._consume(session, buffer)
            code = process.wait()
            self._office(session)
            with session.lock:
                value = session.metadata
                value.update(isComplete=True, finishedTime=int(time.time() * 1000))
                if code == 2:
                    value['wasIncomplete'] = True
                value['isError'] = code not in (0, 1, 2) and bool(value['error'].strip()) and value['totalMatches'] == 0
                _publish(session.directory, value)
        except BaseException as error:
            self._terminate(session)
            session.failure = error
            with session.lock:
                session.metadata.update(isComplete=True, isError=True, wasIncomplete=True,
                                        error='Search storage or collector error: ' + type(error).__name__,
                                        finishedTime=int(time.time() * 1000))
                try:
                    _publish(session.directory, session.metadata)
                except (OSError, ToolError):
                    pass
        finally:
            selector.close()
            for stream in (process.stdout, process.stderr):
                stream.close()
            if session.timer:
                session.timer.cancel()
            if session.early_timer:
                session.early_timer.cancel()
            session.first.set()

    def _office(self, session):
        options = session.metadata['options']
        if options['searchType'] != 'content' or session.cancel.is_set():
            return
        root, pattern = Path(options['rootPath']), options['pattern']
        file_pattern = options['filePattern']
        wanted = []
        for extensions in (('.docx',), ('.xlsx', '.xls', '.xlsm', '.xlsb')):
            if any(str(root).lower().endswith(ext) or ('*' + ext) in file_pattern.lower()
                   or file_pattern.lower().endswith(ext) for ext in extensions):
                wanted.extend(extensions)
        if not wanted:
            return
        if root.is_file():
            files = [root]
        else:
            files = []
            for folder, directories, names in os.walk(root, followlinks=False):
                directories[:] = [name for name in directories if not name.startswith('.') and name != 'node_modules']
                files.extend(Path(folder) / name for name in names if not (Path(folder) / name).is_symlink())
        term = pattern.lower() if options['ignoreCase'] else pattern
        per_family = {'.docx': 0, 'excel': 0}
        for path in files:
            if session.cancel.is_set():
                break
            extension = path.suffix.lower()
            if extension not in wanted:
                continue
            patterns = [part.strip() for part in file_pattern.split('|') if part.strip()]
            if patterns and not any(re.fullmatch(re.escape(part).replace(r'\*', '.*'), path.name, re.I) for part in patterns):
                continue
            family = '.docx' if extension == '.docx' else 'excel'
            maximum = options.get('maxResults', 0)
            try:
                for row in self._document_rows(path):
                    if session.cancel.is_set() or maximum and per_family[family] >= maximum:
                        break
                    text = row['match']
                    index = (text.lower() if options['ignoreCase'] else text).find(term)
                    if index < 0:
                        continue
                    start, end = max(0, index - 50), min(len(text), index + len(term) + 50)
                    row['match'] = ('...' if start else '') + text[start:end] + ('...' if end < len(text) else '')
                    self._commit(session, [(row, False)])
                    per_family[family] += 1
            except Exception:
                continue

    @staticmethod
    def _document_rows(path):
        with zipfile.ZipFile(path) as archive:
            if path.suffix.lower() == '.docx':
                for part in ['word/document.xml', *[f'word/{kind}{number}.xml' for kind in ('header', 'footer') for number in (1, 2, 3)]]:
                    try:
                        xml = archive.read(part).decode('utf-8')
                    except KeyError:
                        continue
                    number = 0
                    for match in re.finditer(r'<w:t(?:\s[^>]*)?>([^<]*)</w:t>', xml):
                        text = match.group(1)
                        if text.strip():
                            number += 1
                            yield {'file': str(path) + (':' + part[5:] if part != 'word/document.xml' else ''),
                                   'line': number, 'match': text, 'type': 'content'}
                return
            ns = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
            relns = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id'
            def text_runs(element):
                return ''.join(item.text or '' for item in
                               [*element.findall('s:t', ns), *element.findall('s:r/s:t', ns)])
            try:
                shared = [text_runs(item) for item in ET.fromstring(archive.read('xl/sharedStrings.xml'))]
            except KeyError:
                shared = []
            relations = {item.attrib['Id']: item.attrib['Target'] for item in ET.fromstring(archive.read('xl/_rels/workbook.xml.rels'))}
            workbook = ET.fromstring(archive.read('xl/workbook.xml'))
            properties = workbook.find('s:workbookPr', ns)
            date_1904 = properties is not None and properties.attrib.get('date1904') in ('1', 'true')
            date_styles = set()
            try:
                styles = ET.fromstring(archive.read('xl/styles.xml'))
                formats = {int(item.attrib['numFmtId']): item.attrib.get('formatCode', '')
                           for item in styles.findall('s:numFmts/s:numFmt', ns)}
                builtin_dates = {*range(14, 23), *range(27, 37), *range(45, 48), *range(50, 59)}
                for index, item in enumerate(styles.findall('s:cellXfs/s:xf', ns)):
                    code = int(item.attrib.get('numFmtId', '0'))
                    custom = re.sub(r'"[^"]*"|\\.|\[[^]]*\]', '', formats.get(code, ''))
                    if code in builtin_dates or re.search(r'[ymdhHsS]', custom):
                        date_styles.add(index)
            except KeyError:
                pass
            for sheet in workbook.findall('s:sheets/s:sheet', ns):
                target = relations[sheet.attrib[relns]]
                member = target.lstrip('/') if target.startswith('/') else 'xl/' + target
                document = ET.fromstring(archive.read(member))
                for row in document.findall('s:sheetData/s:row', ns):
                    values = []
                    for cell in row.findall('s:c', ns):
                        kind = cell.attrib.get('t')
                        value = cell.findtext('s:v', '', ns)
                        if kind == 's':
                            value = shared[int(value)]
                        elif kind == 'inlineStr':
                            value = text_runs(cell.find('s:is', ns))
                        elif kind == 'b':
                            value = 'true' if value == '1' else 'false'
                        elif kind == 'e':
                            value = '[object Object]'
                        elif value and int(cell.attrib.get('s', '0')) in date_styles:
                            value = _excel_date(value, date_1904)
                        elif value:
                            try:
                                value = _js_number(float(value))
                            except (ValueError, OverflowError):
                                pass
                        if value.strip():
                            values.append(value)
                    number = int(row.attrib.get('r', '0'))
                    yield {'file': f'{path}:{sheet.attrib["name"]}!Row{number}', 'line': number,
                           'match': ' '.join(values), 'type': 'content'}

    @staticmethod
    def _runtime(metadata):
        return max(0, int(time.time() * 1000) - metadata['startTime'])

    @staticmethod
    def _format_row(row):
        if row['type'] == 'file':
            return f'📁 {row["file"]}\n'
        match = row.get('match') or ''
        file = row.get('file') if row.get('file') is not None else 'undefined'
        return f'📄 {file}:{row.get("line")} - {match[:100]}{"..." if len(match) > 100 else ""}\n'

    def _get(self, identity):
        with self.lock:
            session = self.sessions.get(identity)
        if session is None:
            raise ToolError(f'Search session {identity} not found')
        return session

    def _read(self, args):
        session = self._get(args.get('sessionId'))
        offset = _number(args.get('offset', 0), 'offset')
        length = _number(args.get('length', 100), 'length')
        with session.lock:
            value = session.metadata
            if value['isError'] and value['totalMatches'] + value['totalContextLines'] == 0 and value['error'].strip():
                return text_result(f'Search session {value["id"]} encountered an error: {value["error"]}', is_error=True)
            if offset < 0:
                rows = session.rows[math.trunc(offset):]
                more = False
                showing = f'Showing last {len(rows)} results'
            else:
                rows = session.rows[math.trunc(offset):math.trunc(offset + length)]
                more = offset + length < len(session.rows) or not value['isComplete']
                showing = f'Showing results {_js_number(offset)}-{_js_number(offset + len(rows) - 1)}'
                value['lastReadTime'] = int(time.time() * 1000)
            total = value['totalMatches'] + value['totalContextLines']
            output = (f'Search session: {value["id"]}\nStatus: {"COMPLETED" if value["isComplete"] else "IN PROGRESS"}\n'
                      f'Runtime: {math.floor(self._runtime(value) / 1000 + 0.5)}s\nTotal results found: {total} ({value["totalMatches"]} matches)\n'
                      + showing + '\n\n')
            if rows:
                output += 'Results:\n' + ''.join(self._format_row(row) for row in rows)
            elif value['isComplete']:
                output += 'No matches found.' if total == 0 else 'No results in this range.'
            else:
                output += 'No results yet, search is still running...'
            if offset >= 0 and more:
                output += f'\n📖 More results available. Use get_more_search_results with offset: {_js_number(offset + len(rows))}'
            if value['isComplete']:
                output += '\n✅ Search completed.'
                if value.get('wasIncomplete') and not value.get('interrupted'):
                    output += '\n⚠️  Warning: Some files were inaccessible due to permissions. Results may be incomplete.'
                if value.get('interrupted'):
                    output += '\nSearch execution was interrupted by controller restart; retained results were not replayed.'
            return text_result(output)

    def _terminate(self, session):
        session.cancel.set()
        process = session.process
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def _stop(self, args):
        session = self.sessions.get(args.get('sessionId'))
        if session is None:
            return text_result(f'Search session {args.get("sessionId")} not found or already completed.')
        self._terminate(session)
        return text_result(f'Search session {session.metadata["id"]} terminated successfully.')

    def _list(self):
        with self.lock:
            sessions = list(self.sessions.values())
        if not sessions:
            return text_result('No active searches.')
        output = f'Active Searches ({len(sessions)}):\n\n'
        for session in sessions:
            with session.lock:
                value = session.metadata
                status = ('❌ ERROR' if value['isError'] else '✅ COMPLETED') if value['isComplete'] else '🔄 RUNNING'
                output += (f'Session: {value["id"]}\n  Type: {value["options"]["searchType"]}\n  Pattern: "{value["options"]["pattern"]}"\n'
                           f'  Status: {status}\n  Runtime: {math.floor(self._runtime(value) / 1000 + 0.5)}s\n'
                           f'  Results: {value["totalMatches"] + value["totalContextLines"]}\n\n')
        return text_result(output)

    async def invoke(self, name, args):
        if self.closed:
            return text_result('Error: search manager is closed', is_error=True)
        handlers = {'start_search': self._start, 'get_more_search_results': self._read,
                    'stop_search': self._stop, 'list_searches': lambda _: self._list()}
        if name not in handlers:
            return text_result('Error: Unknown search tool: ' + str(name), is_error=True)
        try:
            current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in self.state_dir.parts[1:]:
                    following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    os.close(current)
                    current = following
                held, named = os.fstat(self.directory), os.fstat(current)
                _private(named, True)
                if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
                    raise ToolError('search state identity changed; old history was not adopted')
                held, named = os.fstat(self.owner), os.stat('manager.lock', dir_fd=self.directory, follow_symlinks=False)
                _private(named)
                if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
                    raise ToolError('search owner lock identity changed')
            finally:
                os.close(current)
            return await asyncio.to_thread(handlers[name], args)
        except (OSError, ToolError, ValueError) as error:
            prefix = {'start_search': 'Error starting search session: ', 'get_more_search_results': 'Error reading search results: ',
                      'stop_search': 'Error terminating search session: ', 'list_searches': 'Error listing search sessions: '}[name]
            return text_result(prefix + str(error), is_error=True)

    def close(self):
        if self.closed:
            return
        self.closed = True
        with self.lock:
            sessions = list(self.sessions.values())
        for session in sessions:
            self._terminate(session)
        for session in sessions:
            if session.thread is not None:
                session.thread.join()
            if session.process is not None:
                session.process.wait()
            os.close(session.directory)
        os.close(self.owner)
        os.close(self.directory)
