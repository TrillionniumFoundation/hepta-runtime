# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real temporary files and independent parsers; no DC runtime or formal service."""
import asyncio
import base64
import functools
import errno
import hashlib
import http.server
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.filesystem import FileManager, TOOL_NAMES

DOCUMENT_PYTHON = os.environ.get('HEPTA_DOCUMENT_PYTHON', '/home/qian-qi/.local/lib/hepta-runtime/document-env-formats-20261006/bin/python')


def text(result):
    return '\n'.join(block['text'] for block in result['content'] if block['type'] == 'text')


class Config:
    def __init__(self, root):
        self.workspace = root
        self.document_python = DOCUMENT_PYTHON
        self.values = {'allowedDirectories': [str(root)], 'fileReadLineLimit': 1000, 'fileWriteLineLimit': 50}
    def get(self, key, default=None): return self.values.get(key, default)
    def resolve_path(self, raw):
        value = pathlib.Path(raw).expanduser()
        path = (value if value.is_absolute() else self.workspace / value).resolve()
        if not any(path == pathlib.Path(root) or pathlib.Path(root) in path.parents for root in self.values['allowedDirectories']):
            raise ValueError('Path is outside allowed directories')
        return path


class Filesystem(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.config = Config(self.root)
        self.manager = FileManager(self.config)
    async def asyncTearDown(self): self.temp.cleanup()

    async def call(self, name, args):
        result = await self.manager.invoke(name, args)
        self.assertNotIn('isError', result, text(result))
        return result

    def package(self, **members):
        target = self.root / 'book.xlsx'
        with zipfile.ZipFile(target, 'a') as archive:
            for name, content in members.items(): archive.writestr(name, content)

    async def test_all_nine_original_names_and_large_text_without_native_utf8_cap(self):
        self.assertEqual(len(TOOL_NAMES), 9)
        content = '文' * 200000 + '\nlast\n'
        (self.root / 'large.txt').write_text(content)
        reply = await self.call('read_file', {'path': 'large.txt', 'length': 1})
        self.assertIn('文' * 200000, text(reply))
        self.assertNotIn('last', text(reply))

    async def test_positive_and_negative_text_pagination_utf16_and_metadata(self):
        (self.root / 'lines.txt').write_bytes('α\r\nβ\r\nγ\r\nδ\r\n'.encode('utf-16'))
        reply = await self.call('read_file', {'path': 'lines.txt', 'offset': 1, 'length': 2})
        self.assertTrue(text(reply).endswith('β\nγ'))
        tail = await self.call('read_file', {'path': 'lines.txt', 'offset': -2, 'length': 1})
        self.assertTrue(text(tail).endswith('γ\nδ'))
        info = (await self.call('get_file_info', {'path': 'lines.txt'}))['structuredContent']
        self.assertEqual((info['lineCount'], info['lastLine'], info['appendPosition']), (4, 3, 4))

    async def test_write_requires_explicit_existing_mode_append_and_soft_limit(self):
        await self.call('write_file', {'path': 'new.txt', 'content': 'first\n'})
        refused = await self.manager.invoke('write_file', {'path': 'new.txt', 'content': 'lost'})
        self.assertTrue(refused['isError'])
        self.assertEqual((self.root / 'new.txt').read_text(), 'first\n')
        await self.call('write_file', {'path': 'new.txt', 'content': 'second\n', 'mode': 'append'})
        self.config.values['fileWriteLineLimit'] = 2
        response = await self.call('write_file', {'path': 'new.txt', 'content': 'a\nb\nc\nd', 'mode': 'rewrite'})
        self.assertIn('WARNING', text(response))
        self.assertEqual((self.root / 'new.txt').read_text(), 'a\nb\nc\nd')

    async def test_edit_count_crlf_empty_replacement_and_fuzzy_advice_do_not_corrupt(self):
        path = self.root / 'edit.txt'; path.write_bytes(b'alpha\r\nbeta\r\nalpha\r\n')
        reply = await self.call('edit_block', {'file_path': 'edit.txt', 'old_string': 'alpha', 'new_string': 'x'})
        self.assertIn('Expected 1 occurrences but found 2', text(reply)); self.assertEqual(path.read_bytes().count(b'alpha'), 2)
        await self.call('edit_block', {'file_path': 'edit.txt', 'old_string': 'alpha\nbeta', 'new_string': 'A\nB'})
        self.assertTrue(path.read_bytes().startswith(b'A\r\nB\r\n'))
        before = path.read_bytes()
        reply = await self.call('edit_block', {'file_path': 'edit.txt', 'old_string': 'alphx', 'new_string': 'never'})
        self.assertIn('Exact match not found', text(reply)); self.assertEqual(path.read_bytes(), before)
        await self.call('edit_block', {'file_path': 'edit.txt', 'old_string': 'alpha\n', 'new_string': ''})
        self.assertEqual(path.read_bytes(), b'A\r\nB\r\n')

    async def test_mixed_image_batch_keeps_image_blocks_and_per_file_errors(self):
        from PIL import Image
        output = io.BytesIO(); Image.new('RGB', (2, 2), 'red').save(output, 'PNG')
        raw = output.getvalue()
        await self.call('write_file', {'path': 'image.png', 'content': base64.b64encode(raw).decode()})
        (self.root / 'one.txt').write_text('one')
        result = await self.call('read_multiple_files', {'paths': ['one.txt', 'image.png', 'missing.txt']})
        self.assertIn('missing.txt: Error', text(result)); self.assertIn('one', text(result))
        block = next(block for block in result['content'] if block['type'] == 'image')
        self.assertEqual(base64.b64decode(block['data']), raw)
        ui = await self.call('read_file', {'path': 'image.png', 'origin': 'ui'})
        self.assertEqual(ui['structuredContent']['fileType'], 'image')
        self.assertFalse(any(block['type'] == 'image' for block in ui['content']))

    async def test_directory_depth_nested_limit_and_directory_read_fallback(self):
        await self.call('create_directory', {'path': 'a/b/c'})
        for index in range(105): (self.root / 'a/b' / str(index)).write_text('')
        listing = await self.call('list_directory', {'path': 'a', 'depth': 3})
        self.assertIn('[DIR] b', text(listing)); self.assertIn('[WARNING] b:', text(listing))
        top = await self.call('list_directory', {'path': 'a/b', 'depth': 1})
        self.assertNotIn('[WARNING]', text(top)); self.assertIn('[FILE] 104', text(top))
        fallback = await self.call('read_file', {'path': 'a'})
        self.assertIn('This is a directory', text(fallback))

    async def test_nonregular_fifo_and_scope_escape_refuse_without_blocking(self):
        os.mkfifo(self.root / 'fifo')
        for name, args in [('read_file', {'path': 'fifo'}), ('write_file', {'path': 'fifo', 'content': 'x'}),
                           ('edit_block', {'file_path': 'fifo', 'old_string': 'a', 'new_string': 'b'}),
                           ('read_file', {'path': '/etc/passwd'})]:
            reply = await asyncio.wait_for(self.manager.invoke(name, args), 2)
            self.assertTrue(reply['isError'])

    async def test_real_cross_device_move_preserves_bytes_permissions_and_source_removal(self):
        shm = pathlib.Path('/dev/shm')
        if not shm.is_dir() or shm.stat().st_dev == self.root.stat().st_dev: self.skipTest('No distinct writable fixture filesystem')
        with tempfile.TemporaryDirectory(dir=shm) as destination_dir:
            self.config.values['allowedDirectories'].append(destination_dir)
            source = self.root / 'move.txt'; source.write_bytes(b'cross-device\x00exact'); source.chmod(0o640)
            destination = pathlib.Path(destination_dir) / 'moved.txt'
            await self.call('move_file', {'source': str(source), 'destination': str(destination)})
            self.assertFalse(source.exists()); self.assertEqual(destination.read_bytes(), b'cross-device\x00exact')
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)

    async def test_cross_device_source_change_refuses_before_destination_publish_or_source_delete(self):
        source, target = self.root / 'racing.txt', self.root / 'target.txt'
        source.write_text('old'); target.write_text('original destination')
        real_copy = shutil.copy2
        def racing_copy(a, b):
            value = real_copy(a, b)
            source.write_text('new concurrent contents')
            return value
        with mock.patch('dc_compat.filesystem.os.rename', side_effect=OSError(errno.EXDEV, 'fixture')), \
             mock.patch('dc_compat.filesystem.shutil.copy2', side_effect=racing_copy):
            reply = await self.manager.invoke('move_file', {'source': 'racing.txt', 'destination': 'target.txt'})
        self.assertTrue(reply['isError'])
        self.assertEqual(source.read_text(), 'new concurrent contents')
        self.assertEqual(target.read_text(), 'original destination')

    async def test_url_text_image_and_pdf_reads_use_actual_local_http(self):
        from PIL import Image
        (self.root / 'url.txt').write_text('url first\nurl last')
        Image.new('RGB', (2, 2), 'blue').save(self.root / 'url.png')
        await self.call('write_pdf', {'path': 'url.pdf', 'content': '# URL PDF\nFetched safely'})
        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Quiet, directory=self.root))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            prefix = f'http://127.0.0.1:{server.server_port}/'
            body = await self.call('read_file', {'path': prefix + 'url.txt', 'isUrl': True, 'offset': 1, 'length': 1})
            self.assertEqual(text(body), 'url first\nurl last')
            image = await self.call('read_file', {'path': prefix + 'url.png', 'isUrl': True})
            self.assertTrue(any(block['type'] == 'image' for block in image['content']))
            pdf = await self.call('read_file', {'path': prefix + 'url.pdf', 'isUrl': True})
            self.assertIn('URL PDF', text(pdf)); self.assertIn('<!-- Page: 1 -->', text(pdf))
        finally:
            await asyncio.to_thread(server.shutdown); server.server_close(); thread.join(2)

    async def test_docx_creation_xml_paging_edit_and_unrelated_parts_remain_exact(self):
        await self.call('write_file', {'path': 'word.docx', 'content': '# Heading\nKeep this sentence'})
        path = self.root / 'word.docx'
        with zipfile.ZipFile(path, 'a') as archive: archive.writestr('customXml/hepta-preserve.bin', b'\x00unchanged\xff')
        with zipfile.ZipFile(path) as archive: original = {name: archive.read(name) for name in archive.namelist()}
        outline = await self.call('read_file', {'path': 'word.docx'})
        self.assertIn('DOCX Outline', text(outline)); self.assertIn('Heading', text(outline))
        raw = await self.call('read_file', {'path': 'word.docx', 'offset': 1, 'length': 4})
        self.assertIn('DOCX XML', text(raw))
        await self.call('edit_block', {'file_path': 'word.docx', 'old_string': '<w:t>Keep this sentence</w:t>', 'new_string': '<w:t>Edited safely</w:t>'})
        with zipfile.ZipFile(path) as archive:
            self.assertIn(b'Edited safely', archive.read('word/document.xml'))
            for name, data in original.items():
                if name != 'word/document.xml': self.assertEqual(archive.read(name), data)
        before = path.read_bytes()
        refused = await self.manager.invoke('write_file', {'path': 'word.docx', 'content': 'no append', 'mode': 'append'})
        self.assertTrue(refused['isError']); self.assertEqual(path.read_bytes(), before)
        refused = await self.manager.invoke('edit_block', {'file_path': 'word.docx', 'old_string': 'Edited safely', 'new_string': '<broken'})
        self.assertTrue(refused['isError']); self.assertEqual(path.read_bytes(), before)

    async def test_excel_read_range_numeric_sheet_negative_tail_and_append_new_sheet(self):
        await self.call('write_file', {'path': 'book.xlsx', 'content': json.dumps({'Sheet1': [['a', 1], ['b', 2], ['c', 3]], 'My Sheet': [['x', 4]]})})
        reply = await self.call('read_file', {'path': 'book.xlsx', 'range': 'Sheet1!A2:B3', 'length': 2})
        self.assertIn('["b", 2]', text(reply)); self.assertIn('["c", 3]', text(reply))
        tail = await self.call('read_file', {'path': 'book.xlsx', 'offset': -2, 'length': 1})
        self.assertIn('["b", 2]', text(tail)); self.assertIn('["c", 3]', text(tail))
        second = await self.call('read_file', {'path': 'book.xlsx', 'sheet': '1'})
        self.assertIn('["x", 4]', text(second))
        await self.call('write_file', {'path': 'book.xlsx', 'mode': 'append', 'content': json.dumps({'Sheet1': [['d', 4]], 'New Sheet': [['n', 8]]})})
        await self.call('edit_block', {'file_path': 'book.xlsx', 'range': "'New Sheet'!B1", 'content': [[9]]})
        new = await self.call('read_file', {'path': 'book.xlsx', 'range': "'New Sheet'!A1:B1"})
        self.assertIn('["n", 9]', text(new))
        info = (await self.call('get_file_info', {'path': 'book.xlsx'}))['structuredContent']
        self.assertEqual({sheet['name'] for sheet in info['sheets']}, {'Sheet1', 'My Sheet', 'New Sheet'})

    async def test_excel_edit_preserves_cached_formula_other_sheets_styles_and_opaque_parts(self):
        await self.call('write_file', {'path': 'book.xlsx', 'content': json.dumps({'Sheet1': [['edit', '=1+6']], 'Other': [['keep']]})})
        path = self.root / 'book.xlsx'
        with zipfile.ZipFile(path) as archive: members = {name: archive.read(name) for name in archive.namelist()}
        members['xl/worksheets/sheet1.xml'] = members['xl/worksheets/sheet1.xml'].replace(b'<f>1+6</f><v></v>', b'<f>1+6</f><v>7</v>')
        members['xl/embeddings/opaque-fixture.bin'] = b'\x00opaque-format-part\xff'
        with zipfile.ZipFile(path, 'w') as archive:
            for name, value in members.items(): archive.writestr(name, value)
        await self.call('edit_block', {'file_path': 'book.xlsx', 'range': 'Sheet1!A1', 'content': [['changed']]})
        with zipfile.ZipFile(path) as archive:
            for name, value in members.items():
                if name != 'xl/worksheets/sheet1.xml': self.assertEqual(archive.read(name), value)
            self.assertIn(b'<v>7</v>', archive.read('xl/worksheets/sheet1.xml'))
        result = await self.call('read_file', {'path': 'book.xlsx'})
        self.assertIn('["changed", 7]', text(result))

    async def test_true_legacy_biff_read_is_independent_and_unsafe_inplace_edit_refuses(self):
        path = self.root / 'legacy.xls'
        subprocess.run([DOCUMENT_PYTHON, '-c', 'import xlwt,sys;w=xlwt.Workbook();s=w.add_sheet("Data");s.write(0,0,"legacy");s.write(0,1,42);w.save(sys.argv[1])', str(path)], check=True)
        result = await self.call('read_file', {'path': 'legacy.xls'})
        self.assertIn('legacy', text(result)); self.assertIn('42', text(result))
        before = path.read_bytes()
        refused = await self.manager.invoke('edit_block', {'file_path': 'legacy.xls', 'range': 'Data!B1', 'content': [[99]]})
        self.assertTrue(refused['isError']); self.assertEqual(path.read_bytes(), before)

    async def test_xlsm_edit_keeps_original_vba_and_unrelated_zip_members(self):
        await self.call('write_file', {'path': 'macro.xlsm', 'content': '[["before"]]'})
        path = self.root / 'macro.xlsm'
        with zipfile.ZipFile(path, 'a') as archive:
            archive.writestr('xl/vbaProject.bin', b'owned-fixture-vba-payload\x00\xff')
        with zipfile.ZipFile(path) as archive: original = {name: archive.read(name) for name in archive.namelist()}
        await self.call('edit_block', {'file_path': 'macro.xlsm', 'range': 'Sheet1!A1', 'content': [['after']]})
        with zipfile.ZipFile(path) as archive:
            for name, value in original.items():
                if name != 'xl/worksheets/sheet1.xml': self.assertEqual(archive.read(name), value)

    async def test_pdf_markdown_image_pages_insert_delete_outputpath_and_preserve_original(self):
        from PIL import Image
        Image.new('RGB', (10, 10), 'green').save(self.root / 'inline.png')
        content = '# First page\n![image](inline.png)\n<div style="break-before:page"></div>\n\n# Second page\nTwo'
        await self.call('write_pdf', {'path': 'pages.pdf', 'content': content})
        original = (self.root / 'pages.pdf').read_bytes()
        info = (await self.call('get_file_info', {'path': 'pages.pdf'}))['structuredContent']
        self.assertEqual(info['totalPages'], 2)
        read = await self.call('read_file', {'path': 'pages.pdf', 'offset': 1, 'length': 1})
        self.assertIn('Second page', text(read)); self.assertNotIn('First page', text(read))
        full = await self.call('read_file', {'path': 'pages.pdf'})
        self.assertTrue(any(block['type'] == 'image' for block in full['content']))
        await self.call('write_pdf', {'path': 'pages.pdf', 'outputPath': 'modified.pdf', 'content': [
            {'type': 'delete', 'pageIndexes': [-1]}, {'type': 'insert', 'pageIndex': 1, 'markdown': '# Inserted page\nAdded'}]})
        modified = await self.call('read_file', {'path': 'modified.pdf'})
        self.assertIn('Inserted page', text(modified)); self.assertNotIn('Second page', text(modified))
        self.assertEqual((self.root / 'pages.pdf').read_bytes(), original)
        bad = await self.manager.invoke('write_pdf', {'path': 'pages.pdf', 'content': [{'type': 'insert', 'pageIndex': 100, 'sourcePdfPath': 'modified.pdf'}]})
        self.assertTrue(bad['isError']); self.assertEqual((self.root / 'pages.pdf').read_bytes(), original)

    async def test_pdf_resource_outside_allowed_roots_refuses_before_publication(self):
        with tempfile.TemporaryDirectory() as outside:
            from PIL import Image
            image = pathlib.Path(outside) / 'secret.png'; Image.new('RGB', (2, 2), 'red').save(image)
            result = await self.manager.invoke('write_pdf', {'path': 'refused.pdf', 'content': f'![outside]({image.as_uri()})'})
            self.assertTrue(result['isError']); self.assertFalse((self.root / 'refused.pdf').exists())


if __name__ == '__main__': unittest.main()
