# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent DC file tools with streamed text reads and isolated format helpers."""
from __future__ import annotations
import asyncio
import base64
import collections
import copy
import datetime
import difflib
import errno
import itertools
import json
import mimetypes
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from .registry import ToolError, text_result

TOOL_NAMES = frozenset({'read_file', 'read_multiple_files', 'write_file', 'write_pdf',
                       'create_directory', 'list_directory', 'move_file', 'get_file_info', 'edit_block'})
IMAGES = {'.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
          '.webp': 'image/webp', '.bmp': 'image/bmp', '.svg': 'image/svg+xml'}
DOCUMENTS = {'.pdf', '.docx', '.xlsx', '.xlsm', '.xls'}


def _number(value, name, default=0):
    value = default if value is None else value
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not float(value).is_integer():
        raise ToolError(name + ' must be an integer')
    return int(value)


def _write_atomic(path, data):
    path = pathlib.Path(path)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o666 & ~_umask()
    descriptor, name = tempfile.mkstemp(prefix='.hepta-write-', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        if path.exists():
            shutil.copystat(path, name)
            os.utime(name, None)
        os.replace(name, path)
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass


def _umask():
    # Linux exposes the current mask without changing the process-global mask.
    try:
        for line in pathlib.Path('/proc/self/status').read_text().splitlines():
            if line.startswith('Umask:'): return int(line.split()[1], 8)
    except OSError: pass
    return 0o022


def _encoding(head):
    if head.startswith(b'\xff\xfe'): return 'utf-16'
    if head.startswith(b'\xfe\xff'): return 'utf-16'
    if head.startswith(b'\xef\xbb\xbf'): return 'utf-8-sig'
    return 'utf-8'


def _binary(head):
    if _encoding(head) != 'utf-8': return False
    if b'\x00' in head: return True
    return bool(head) and sum(byte < 9 or 13 < byte < 32 for byte in head) / len(head) > 0.1


class FileManager:
    tool_names = TOOL_NAMES

    def __init__(self, config, document_python=None):
        self.config = config
        self.document_python = str(document_python or getattr(config, 'document_python', '') or '')
        self._locks, self._lock = {}, threading.Lock()
        self._mutation_lock = threading.RLock()

    def _path(self, value):
        if not isinstance(value, str) or not value: raise ToolError('A nonempty file path is required')
        return pathlib.Path(self.config.resolve_path(value))

    def _path_lock(self, path):
        with self._lock: return self._locks.setdefault(str(path), threading.RLock())

    def _helper(self, operation, path, args):
        if not self.document_python:
            raise ToolError('Configure an independent document_python with the required Office/PDF parsers')
        request = {'operation': operation, 'path': str(path), 'arguments': args,
                   'workspace': str(self.config.workspace),
                   'allowed_directories': self.config.get('allowedDirectories', [str(self.config.workspace)])}
        helper = pathlib.Path(__file__).with_name('filesystem_document_helper.py')
        result = subprocess.run([self.document_python, '-I', str(helper)],
            input=json.dumps(request, ensure_ascii=False).encode(), capture_output=True, timeout=180)
        if result.returncode != 0:
            raise ToolError('Document helper failed: ' + str(result.returncode))
        try: reply = json.loads(result.stdout)
        except ValueError as exc: raise ToolError('Invalid response from the independent document helper') from exc
        if reply.get('ok') is not True: raise ToolError(reply.get('error', 'Document operation refused'))
        return reply['value']

    def _ui(self, args, path, file_type):
        if args.get('origin') != 'ui': return {}
        return {'structuredContent': {'fileName': pathlib.Path(path).name, 'filePath': str(path), 'fileType': file_type}}

    def _format_document(self, path, args, document):
        if document.get('kind') != 'pdf':
            return {**text_result(document['text']), **self._ui(args, path, 'unsupported')}
        author = ', Author: ' + document['author'] if document.get('author') else ''
        title = ', Title: ' + document['title'] if document.get('title') else ''
        blocks = [{'type': 'text', 'text': f'PDF file: {args["path"]}{author}{title} ({document["totalPages"]} pages) \n'}]
        for page in document['pages']:
            blocks.extend(page.get('images', []))
            blocks.append({'type': 'text', 'text': f'<!-- Page: {page["pageNumber"]} -->\n{page["text"]}'})
        return {'content': blocks, **self._ui(args, path, 'unsupported')}

    def _text_read(self, path, args):
        offset = _number(args.get('offset'), 'offset')
        length = _number(args.get('length'), 'length', self.config.get('fileReadLineLimit', 1000))
        if length < 0: raise ToolError('length must be nonnegative')
        with path.open('rb') as stream: head = stream.read(4096)
        if _binary(head):
            return text_result(f'Cannot read binary file as text: {path.name}\n\nUse start_process + interact_with_process with an appropriate binary format parser.')
        encoding = _encoding(head)
        size = path.stat().st_size
        def lines():
            with path.open('r', encoding=encoding, errors='replace', newline=None) as stream:
                for line in stream: yield line.rstrip('\n')
        if offset < 0:
            chosen = list(collections.deque(lines(), maxlen=abs(offset)))
        else:
            chosen = list(itertools.islice(lines(), offset, offset + length))
        total = sum(1 for _ in lines()) if size < 10 * 1024 * 1024 else None
        if offset < 0:
            status = f'[Reading last {len(chosen)} lines' + (f' (total: {total} lines)]' if total is not None else ']')
        else:
            where = 'start' if offset == 0 else 'line ' + str(offset)
            status = f'[Reading {len(chosen)} lines from {where}'
            status += f' (total: {total} lines, {max(0, total - offset - len(chosen))} remaining)]' if total is not None else ']'
        return {**text_result(status + '\n\n' + '\n'.join(chosen)), **self._ui(args, path, 'text')}

    def _url_read(self, args):
        url = args['path']
        if urllib.parse.urlsplit(url).scheme not in ('http', 'https'):
            raise ToolError('URL reads support http and https')
        deadline = time.monotonic() + 30
        with urllib.request.urlopen(url, timeout=30) as response:
            mime = response.headers.get_content_type()
            chunks = []
            while True:
                if time.monotonic() > deadline: raise ToolError('URL fetch timed out after 30000ms')
                chunk = response.read1(65536)
                if not chunk: break
                chunks.append(chunk)
            data = b''.join(chunks)
            encoding = response.headers.get_content_charset() or 'utf-8'
        if mime == 'application/pdf' or urllib.parse.urlsplit(url).path.lower().endswith('.pdf'):
            with tempfile.TemporaryDirectory(prefix='hepta-url-pdf-') as directory:
                path = pathlib.Path(directory) / 'download.pdf'; path.write_bytes(data)
                document = self._helper('read', path, {**args, 'offset': 0, 'length': None})
                return self._format_document(url, args, document)
        if mime.startswith('image/'):
            if args.get('origin') == 'ui': return text_result(base64.b64encode(data).decode())
            return {'content': [{'type': 'text', 'text': f'Image file: {url} ({mime})\n'},
                                {'type': 'image', 'data': base64.b64encode(data).decode(), 'mimeType': mime}]}
        return text_result(data.decode(encoding, 'replace'))

    def _read(self, args):
        if args.get('isUrl'): return self._url_read(args)
        path = self._path(args.get('path'))
        if path.is_dir():
            listing = self._directory({'path': str(path), 'depth': 2})
            if args.get('origin') == 'ui': return {**listing, **self._ui(args, path, 'directory')}
            return text_result('This is a directory, not a file. Use the list_directory tool instead of read_file for directories.\n\n' + listing['content'][0]['text'])
        if not path.is_file(): raise ToolError('File not found or not a regular file: ' + str(path))
        suffix = path.suffix.lower()
        if suffix in IMAGES:
            data = base64.b64encode(path.read_bytes()).decode()
            if args.get('origin') == 'ui':
                return {**text_result(data), **self._ui(args, path, 'image')}
            return {'content': [{'type': 'text', 'text': f'Image file: {args["path"]} ({IMAGES[suffix]})\n'},
                                {'type': 'image', 'data': data, 'mimeType': IMAGES[suffix]}]}
        if suffix in DOCUMENTS:
            parsed = dict(args)
            parsed.setdefault('length', self.config.get('fileReadLineLimit', 1000))
            return self._format_document(path, args, self._helper('read', path, parsed))
        return self._text_read(path, args)

    def _multiple(self, args):
        paths = args.get('paths')
        if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
            raise ToolError('paths must be an array of strings')
        summary, blocks = [], []
        for path in paths:
            try:
                result = self._read({'path': path})
                summary.append(f'{path}: ' + ('image' if any(block['type'] == 'image' for block in result['content']) else 'text'))
                blocks.append({'type': 'text', 'text': f'\n--- {path} ---\n'})
                blocks.extend(result['content'])
            except Exception as error:
                summary.append(f'{path}: Error - {error}')
        return {'content': [{'type': 'text', 'text': '\n'.join(summary)}, *blocks]}

    def _write(self, args):
        path, content = self._path(args.get('path')), args.get('content')
        if not isinstance(content, str): raise ToolError('content must be a string')
        mode = args.get('mode', 'rewrite')
        if mode not in ('rewrite', 'append'): raise ToolError('mode must be rewrite or append')
        with self._path_lock(path):
            if path.exists() and not path.is_file(): raise ToolError('Write destination is not a regular file')
            if 'mode' not in args and path.is_file() and path.stat().st_size > 0:
                raise ToolError(f"Write rejected to prevent accidental data loss: {path} already has content; explicitly choose mode 'append' or 'rewrite'")
            if path.suffix.lower() in DOCUMENTS:
                self._helper('write', path, args)
            elif path.suffix.lower() in IMAGES:
                raw = content.encode().translate(None, b' \r\n\t').replace(b'-', b'+').replace(b'_', b'/')
                _write_atomic(path, base64.b64decode(raw + b'=' * (-len(raw) % 4)))
            else:
                if path.exists():
                    with path.open('rb') as stream:
                        if _binary(stream.read(4096)): raise ToolError('Cannot write binary files directly; use a format-specific process')
                if mode == 'append':
                    with path.open('ab') as stream: stream.write(content.encode()); stream.flush(); os.fsync(stream.fileno())
                else: _write_atomic(path, content.encode())
        lines = len(content.splitlines())
        warning = f'\nWARNING: {lines} lines exceeds fileWriteLineLimit {self.config.get("fileWriteLineLimit", 50)}; content was written.' if lines > self.config.get('fileWriteLineLimit', 50) else ''
        return {**text_result(f'Successfully wrote to {path}{warning}'), **self._ui(args, path, 'unsupported' if path.suffix.lower() in DOCUMENTS else 'text')}

    def _directory(self, args):
        root = self._path(args.get('path'))
        depth = _number(args.get('depth'), 'depth', 2)
        result = []
        def visit(directory, remaining, relative='', top=False):
            if remaining <= 0: return
            try: entries = sorted(os.scandir(directory), key=lambda item: item.name)
            except FileNotFoundError: result.append(f'[NOT_FOUND] {relative or directory.name} — path does not exist'); return
            except OSError: result.append(f'[DENIED] {relative or directory.name} — not accessible'); return
            total = len(entries)
            if not top: entries = entries[:100]
            for entry in entries:
                name = str(pathlib.Path(relative) / entry.name) if relative else entry.name
                is_directory = entry.is_dir(follow_symlinks=False)
                result.append(('[DIR] ' if is_directory else '[FILE] ') + name)
                if is_directory and remaining > 1:
                    try: allowed = self._path(str(pathlib.Path(directory) / entry.name))
                    except Exception: continue
                    visit(allowed, remaining - 1, name)
            if not top and total > 100: result.append(f'[WARNING] {relative}: {total - 100} items hidden (showing first 100 of {total} total)')
        visit(root, depth, top=True)
        return text_result('\n'.join(result))

    def _info(self, args):
        path = self._path(args.get('path')); info = path.stat()
        def stamp(value): return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
        result = {'size': info.st_size, 'created': stamp(getattr(info, 'st_birthtime', info.st_ctime)),
                  'modified': stamp(info.st_mtime), 'accessed': stamp(info.st_atime), 'isDirectory': path.is_dir(),
                  'isFile': path.is_file(), 'permissions': oct(stat.S_IMODE(info.st_mode))[2:].zfill(3), 'fileType': 'text'}
        if path.is_file():
            if path.suffix.lower() in IMAGES: result.update(fileType='image', isImage=True)
            elif path.suffix.lower() in DOCUMENTS:
                result.update(self._helper('info', path, args))
            else:
                with path.open('rb') as stream: head = stream.read(4096)
                if _binary(head): result.update(fileType='binary', isBinary=True)
                elif info.st_size < 10 * 1024 * 1024:
                    with path.open('r', encoding=_encoding(head), errors='replace', newline=None) as stream: count = sum(1 for _ in stream)
                    result.update(lineCount=count, lastLine=count - 1, appendPosition=count)
        return text_result('\n'.join(f'{key}: {json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else str(value).lower() if isinstance(value, bool) else value}' for key, value in result.items()), structured=result)

    def _move(self, args):
        source, destination = self._path(args.get('source')), self._path(args.get('destination'))
        if source == destination: return text_result(f'Successfully moved {source} to {destination}')
        try: os.rename(source, destination)
        except OSError as error:
            if error.errno != errno.EXDEV: raise
            # Copy all content and metadata to the destination device before
            # publishing it. An incomplete copy never replaces the destination.
            temporary = pathlib.Path(tempfile.mkdtemp(prefix='.hepta-move-', dir=destination.parent)) / 'payload'
            def inventory():
                members = [source, *source.rglob('*')] if source.is_dir() else [source]
                return {str(member.relative_to(source)) if member != source else '.':
                    (record.st_dev, record.st_ino, record.st_mode, record.st_size, record.st_mtime_ns, record.st_ctime_ns)
                    for member in members for record in [member.lstat()]}
            before = inventory()
            try:
                if source.is_dir(): shutil.copytree(source, temporary, symlinks=True)
                elif source.is_symlink(): temporary.symlink_to(os.readlink(source))
                else: shutil.copy2(source, temporary)
                if inventory() != before:
                    raise ToolError('Source changed during cross-device copy; destination was not replaced and source was retained')
                os.replace(temporary, destination)
                try:
                    if source.is_dir(): shutil.rmtree(source)
                    else: source.unlink()
                except OSError as cleanup_error:
                    raise ToolError('Destination was published; source cleanup is incomplete. Inspect both paths before retrying') from cleanup_error
            finally: shutil.rmtree(temporary.parent)
        return text_result(f'Successfully moved {source} to {destination}')

    def _pdf(self, args):
        path = self._path(args.get('path')); parsed = dict(args)
        if isinstance(parsed.get('content'), str) and parsed['content'].lstrip().startswith('['):
            try: parsed['content'] = json.loads(parsed['content'])
            except ValueError: pass
        if parsed.get('outputPath'): parsed['outputPath'] = str(self._path(parsed['outputPath']))
        if isinstance(parsed.get('content'), list):
            parsed['content'] = [dict(operation) for operation in parsed['content']]
            for operation in parsed['content']:
                if operation.get('sourcePdfPath'): operation['sourcePdfPath'] = str(self._path(operation['sourcePdfPath']))
        with self._path_lock(path): self._helper('pdf', path, parsed)
        return text_result('Successfully wrote PDF to ' + str(parsed.get('outputPath') or path))

    def _edit(self, args):
        path = self._path(args.get('file_path'))
        with self._path_lock(path):
            if not path.is_file(): raise ToolError('Edit source is not a regular file')
            if path.suffix.lower() in DOCUMENTS:
                parsed = dict(args)
                if path.suffix.lower() == '.pdf':
                    parsed['path'] = str(path)
                    if isinstance(parsed.get('content'), list):
                        for operation in parsed['content']:
                            if operation.get('sourcePdfPath'): operation['sourcePdfPath'] = str(self._path(operation['sourcePdfPath']))
                self._helper('edit', path, parsed)
                return text_result('Successfully edited ' + str(path))
            old, new = args.get('old_string'), args.get('new_string')
            if not isinstance(old, str) or not old or not isinstance(new, str):
                raise ToolError('edit_block requires nonempty old_string and a new_string')
            raw = path.read_bytes(); encoding = _encoding(raw[:4096]); content = raw.decode(encoding)
            if _binary(raw[:4096]): raise ToolError('Cannot edit an unsupported binary file as text')
            line_ending = '\r\n' if '\r\n' in content else '\r' if '\r' in content else '\n'
            normalize = lambda value: re.sub(r'\r\n|\r|\n', line_ending, value)
            old, new = normalize(old), normalize(new)
            count = sum(1 for _ in re.finditer('(?=' + re.escape(old) + ')', content))
            expected = _number(args.get('expected_replacements'), 'expected_replacements', 1)
            if count != expected:
                if count: return text_result(f'Expected {expected} occurrences but found {count} in {path}. Set expected_replacements explicitly to replace all.')
                candidates = content.splitlines(keepends=True)
                width = max(1, len(old.splitlines()))
                best = max((''.join(candidates[index:index + width]) for index in range(len(candidates))),
                           key=lambda candidate: difflib.SequenceMatcher(None, old, candidate).ratio(), default='')
                ratio = difflib.SequenceMatcher(None, old, best).ratio()
                return text_result(f'Exact match not found. Closest text ({ratio:.0%} similarity):\n{best}\nUse the exact text found in the file; no change was made.')
            _write_atomic(path, content.replace(old, new).encode(encoding))
        return text_result('Successfully edited ' + str(path))

    async def invoke(self, name, arguments):
        handlers = {'read_file': self._read, 'read_multiple_files': self._multiple, 'write_file': self._write,
                    'write_pdf': self._pdf, 'list_directory': self._directory, 'move_file': self._move,
                    'get_file_info': self._info, 'edit_block': self._edit,
                    'create_directory': lambda args: self._mkdir(args)}
        if name not in handlers: raise ToolError('Unknown filesystem tool: ' + str(name))
        arguments = copy.deepcopy(arguments)
        def run():
            if name in {'write_file', 'write_pdf', 'create_directory', 'move_file', 'edit_block'}:
                with self._mutation_lock: return handlers[name](arguments)
            return handlers[name](arguments)
        try: return await asyncio.to_thread(run)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            return text_result('Error: ' + str(error), is_error=True)

    def _mkdir(self, args):
        path = self._path(args.get('path')); path.mkdir(parents=True, exist_ok=True)
        return text_result('Successfully created directory ' + str(path))
