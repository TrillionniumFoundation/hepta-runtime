# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fresh files and real rg subprocesses only; no installed service or old search."""
from __future__ import annotations
import asyncio
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.searches import SearchManager, build_rg_args, parse_rg_line
from dc_compat.registry import ToolRegistry


class Config:
    def __init__(self, workspace):
        self.workspace = workspace
        self.document_python = sys.executable

    def get(self, key, default=None):
        return default

    def resolve_path(self, raw):
        path = (self.workspace / raw).resolve(strict=True) if not Path(raw).is_absolute() else Path(raw).resolve(strict=True)
        if not path.is_relative_to(self.workspace):
            raise ValueError('path is outside the fixture workspace')
        return path


class SearchTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.data = self.base / 'data'
        self.data.mkdir(mode=0o700)
        self.config = Config(self.data)
        self.manager = SearchManager(self.base / 'state', self.config)

    async def asyncTearDown(self):
        await asyncio.to_thread(self.manager.close)
        self.temporary.cleanup()

    async def start(self, **options):
        args = {'path': str(self.data), 'pattern': 'needle', 'timeout_ms': 0, **options}
        result = await self.manager.invoke('start_search', args)
        self.assertFalse(result.get('isError'), result)
        return re.search(r'session: (search_[0-9]+_[0-9]+)', result['content'][0]['text']).group(1)

    async def finish(self, identity):
        session = self.manager.sessions[identity]
        end = time.monotonic() + 10
        while not session.metadata['isComplete'] and time.monotonic() < end:
            await asyncio.sleep(0.01)
        self.assertTrue(session.metadata['isComplete'])
        self.assertIsNone(session.failure)
        with session.lock:
            return copy.deepcopy(session.rows)

    async def page(self, identity, **arguments):
        result = await self.manager.invoke('get_more_search_results', {'sessionId': identity, **arguments})
        self.assertFalse(result.get('isError'), result)
        return result['content'][0]['text']

    def file(self, name, text):
        path = self.data / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    async def test_default_content_regex_case_and_five_context_lines_match_real_rg(self):
        self.file('a.txt', '\n'.join(['before'] * 8 + ['NEEDLE123'] + ['after'] * 8) + '\n')
        identity = await self.start(pattern='needle[0-9]+', searchType='content')
        rows = await self.finish(identity)
        output = subprocess.check_output(['/usr/bin/rg', '--json', '--line-number', '-C', '5', '-i', '--',
                                          'needle[0-9]+', str(self.data)], text=True)
        expected = []
        for line in output.splitlines():
            value = json.loads(line)
            if value['type'] not in ('match', 'context'):
                continue
            item = value['data']
            text = item['submatches'][0]['match']['text'] if value['type'] == 'match' else item['lines']['text'].strip()
            expected.append({'file': item['path']['text'], 'line': item['line_number'], 'match': text, 'type': 'content'})
        self.assertEqual(rows, expected)
        self.assertEqual(len(rows), 11)
        self.assertEqual(self.manager.sessions[identity].metadata['totalMatches'], 1)
        self.assertEqual(self.manager.sessions[identity].metadata['totalContextLines'], 10)

    async def test_literal_and_case_sensitive_are_explicit_options(self):
        self.file('a.txt', 'foo.bar\nfooXbar\nFOO.BAR\n')
        regex = await self.start(pattern='foo.bar', searchType='content', contextLines=0)
        literal = await self.start(pattern='foo.bar', searchType='content', contextLines=0,
                                   literalSearch=True, ignoreCase=False)
        self.assertEqual(len(await self.finish(regex)), 3)
        self.assertEqual([row['line'] for row in await self.finish(literal)], [1])

    async def test_file_default_fuzzy_case_and_ordered_file_pattern_match_real_rg(self):
        self.file('Alpha.TXT', 'x')
        self.file('alpha.js', 'x')
        self.file('unrelated.txt', 'x')
        identity = await self.start(pattern='alpha')
        self.assertEqual({Path(row['file']).name for row in await self.finish(identity)}, {'Alpha.TXT', 'alpha.js'})
        identity = await self.start(pattern='*.js', filePattern='*.txt', earlyTermination=False)
        expected = subprocess.check_output(['/usr/bin/rg', '--files', '--iglob', '*.txt', '--iglob', '*.js', str(self.data)], text=True)
        self.assertEqual({row['file'] for row in await self.finish(identity)}, set(expected.splitlines()))

    async def test_hidden_ignore_and_glob_filters_use_rg_without_reimplementation(self):
        (self.data / '.git').mkdir()
        self.file('.gitignore', 'ignored/\n')
        self.file('.hidden.txt', 'needle')
        self.file('visible.txt', 'needle')
        self.file('ignored/a.txt', 'needle')
        basic = await self.start(pattern='*.txt', earlyTermination=False)
        hidden = await self.start(pattern='*.txt', includeHidden=True, earlyTermination=False)
        for identity, extra in [(basic, []), (hidden, ['--hidden'])]:
            expected = subprocess.check_output(['/usr/bin/rg', '--files', *extra, '--iglob', '*.txt', str(self.data)], text=True)
            self.assertEqual({row['file'] for row in await self.finish(identity)}, set(expected.splitlines()))
        # Explicit positive globs can include a hidden basename even without
        # --hidden. Preserve rg/DC behavior instead of filtering it a second time.
        self.assertIn('.hidden.txt', {Path(row['file']).name for row in self.manager.sessions[basic].rows})

    async def test_content_file_pattern_keeps_case_sensitive_g_even_when_text_folds_case(self):
        self.file('a.TXT', 'needle\n')
        self.file('b.txt', 'NEEDLE\n')
        identity = await self.start(searchType='content', filePattern='*.txt', contextLines=0)
        self.assertEqual([Path(row['file']).name for row in await self.finish(identity)], ['b.txt'])

    async def test_zero_means_no_thousand_row_or_time_ceiling_and_tail_ignores_length(self):
        self.file('a.txt', ''.join(f'needle{i}\n' for i in range(1507)))
        identity = await self.start(searchType='content', pattern='needle[0-9]+', maxResults=0,
                                    timeout_ms=0, contextLines=0)
        rows = await self.finish(identity)
        self.assertEqual(len(rows), 1507)
        tail = await self.page(identity, offset=-3, length=1)
        self.assertIn('Showing last 3 results', tail)
        self.assertIn('needle1504', tail)
        self.assertIn('needle1506', tail)
        self.assertNotIn('More results available', tail)
        full = await self.page(identity, offset=0, length=2000)
        self.assertEqual(full.count('📄 '), 1507)

    async def test_max_results_is_rg_per_file_not_an_extra_global_limit(self):
        self.file('a.txt', 'needle\n' * 8)
        self.file('b.txt', 'needle\n' * 8)
        identity = await self.start(searchType='content', contextLines=0, maxResults=2)
        self.assertEqual(len(await self.finish(identity)), 4)

    async def test_range_pages_are_independent_and_can_repeat_without_consumption(self):
        self.file('a.txt', ''.join(f'needle{i}\n' for i in range(25)))
        identity = await self.start(searchType='content', pattern='needle[0-9]+', contextLines=0)
        await self.finish(identity)
        first = await self.page(identity, offset=2, length=3)
        await self.page(identity, offset=19, length=2)
        again = await self.page(identity, offset=2, length=3)
        self.assertEqual([line for line in first.splitlines() if line.startswith('📄')],
                         [line for line in again.splitlines() if line.startswith('📄')])
        self.assertIn('offset: 5', first)

    async def test_large_real_file_streams_progressively_and_stop_terminates_owned_rg(self):
        self.file('large.txt', 'needle\n' * 500000)
        identity = await self.start(searchType='content', contextLines=0)
        session = self.manager.sessions[identity]
        end = time.monotonic() + 5
        while not session.rows and time.monotonic() < end:
            await asyncio.sleep(0.01)
        self.assertTrue(session.rows)
        self.assertFalse(session.metadata['isComplete'])
        page = await self.page(identity, offset=0, length=4)
        self.assertIn('Status: IN PROGRESS', page)
        self.assertIn('More results available', page)
        result = await self.manager.invoke('stop_search', {'sessionId': identity})
        self.assertIn('terminated successfully', result['content'][0]['text'])
        retained = await self.finish(identity)
        self.assertLess(len(retained), 500000)
        self.assertIsNotNone(session.process.poll())
        self.assertIn('✅ Search completed.', await self.page(identity, offset=-4))

    async def test_explicit_timeout_terminates_a_real_blocked_child(self):
        fifo = self.data / 'stream'
        os.mkfifo(fifo, 0o600)
        keep_open = os.open(fifo, os.O_RDWR)
        try:
            identity = await self.start(path=str(fifo), searchType='content', timeout_ms=40, contextLines=0)
            await self.finish(identity)
            self.assertIsNotNone(self.manager.sessions[identity].process.poll())
            self.assertTrue(self.manager.sessions[identity].cancel.is_set())
        finally:
            os.close(keep_open)

    async def test_completed_journal_restarts_read_only_and_never_relaunches_rg(self):
        self.file('a.txt', 'needle\n' * 15)
        identity = await self.start(searchType='content', contextLines=0)
        rows = await self.finish(identity)
        await asyncio.to_thread(self.manager.close)
        with mock.patch('dc_compat.searches.subprocess.Popen', side_effect=AssertionError('no replay')):
            self.manager = SearchManager(self.base / 'state', self.config)
            self.assertEqual(self.manager.sessions[identity].rows, rows)
            self.assertEqual((await self.page(identity, offset=-100)).count('📄 '), 15)
            listing = await self.manager.invoke('list_searches', {})
            self.assertIn(identity, listing['content'][0]['text'])

    async def test_interrupted_journal_recovery_keeps_prefix_without_inventing_completion(self):
        self.file('a.txt', 'needle\n' * 4)
        identity = await self.start(searchType='content', contextLines=0)
        rows = await self.finish(identity)
        await asyncio.to_thread(self.manager.close)
        path = self.base / 'state' / identity / 'metadata.json'
        value = json.loads(path.read_text())
        value['isComplete'] = False
        path.write_text(json.dumps(value))
        with mock.patch('dc_compat.searches.subprocess.Popen', side_effect=AssertionError('no replay')):
            self.manager = SearchManager(self.base / 'state', self.config)
            self.assertEqual(self.manager.sessions[identity].rows, rows)
            result = await self.page(identity)
            self.assertIn('interrupted by controller restart', result)
            self.assertIn('retained results were not replayed', result)

    async def test_official_docx_trigger_and_literal_body_header_search_without_pdf_extraction(self):
        path = self.data / 'a.docx'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('word/document.xml', '<w:document><w:t>foo.bar literal</w:t><w:t>fooXbar</w:t></w:document>')
            archive.writestr('word/header1.xml', '<w:hdr><w:t>foo.bar header</w:t></w:hdr>')
        identity = await self.start(searchType='content', pattern='foo.bar', filePattern='*.docx', contextLines=0)
        rows = await self.finish(identity)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row['match'] for row in rows}, {'foo.bar literal', 'foo.bar header'})
        self.assertTrue(any(row['file'].endswith(':header1.xml') for row in rows))
        plain = await self.start(searchType='content', pattern='foo.bar', contextLines=0)
        self.assertEqual(await self.finish(plain), [])

    async def test_official_xlsx_cross_column_shared_string_and_cached_formula_rows(self):
        path = self.data / 'a.xlsx'
        ns = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('xl/workbook.xml', f'<workbook xmlns="{ns}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Data" r:id="r1"/></sheets></workbook>')
            archive.writestr('xl/_rels/workbook.xml.rels', '<Relationships><Relationship Id="r1" Target="worksheets/sheet1.xml"/></Relationships>')
            archive.writestr('xl/sharedStrings.xml', f'<sst xmlns="{ns}"><si><t>hello</t></si><si><r><t>world</t></r></si></sst>')
            archive.writestr('xl/worksheets/sheet1.xml', f'<worksheet xmlns="{ns}"><sheetData><row r="1"><c t="s"><v>0</v></c><c t="s"><v>1</v></c><c><f>1+1</f><v>2</v></c></row></sheetData></worksheet>')
        identity = await self.start(searchType='content', pattern='hello world 2', filePattern='*.xlsx', contextLines=0)
        rows = await self.finish(identity)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]['file'].endswith(':Data!Row1'))
        self.assertEqual(rows[0]['match'], 'hello world 2')

    async def test_xlsx_date_boolean_error_and_inline_rich_text_use_official_value_projection(self):
        path = self.data / 'values.xlsx'
        ns = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('xl/workbook.xml', f'<workbook xmlns="{ns}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Data" r:id="r1"/></sheets></workbook>')
            archive.writestr('xl/_rels/workbook.xml.rels', '<Relationships><Relationship Id="r1" Target="worksheets/sheet1.xml"/></Relationships>')
            archive.writestr('xl/styles.xml', f'<styleSheet xmlns="{ns}"><cellXfs><xf numFmtId="0"/><xf numFmtId="14"/></cellXfs></styleSheet>')
            archive.writestr('xl/worksheets/sheet1.xml', f'<worksheet xmlns="{ns}"><sheetData><row r="1"><c s="1"><v>45292.5</v></c><c t="b"><v>1</v></c><c t="e"><v>#DIV/0!</v></c><c t="inlineStr"><is>\n<r><t>hello</t></r>\n<r><t>world</t></r>\n</is></c></row></sheetData></worksheet>')
        identity = await self.start(searchType='content', pattern='true [object Object] helloworld',
                                    filePattern='*.xlsx', contextLines=0)
        rows = await self.finish(identity)
        self.assertEqual(len(rows), 1)
        self.assertIn('2024', rows[0]['match'])
        self.assertIn('GMT', rows[0]['match'])
        self.assertTrue(rows[0]['match'].endswith('true [object Object] helloworld'))

    async def test_registry_keeps_exact_catalog_schema_and_returns_full_mcp_results(self):
        registry = ToolRegistry(Path(__file__).resolve().parents[1] / 'deploy/dc_compat/catalog.json')
        registry.add(self.manager)
        self.assertEqual(registry.implemented_tools, self.manager.tool_names)
        self.assertEqual(await registry.invoke('list_searches', {}), {'content': [{'type': 'text', 'text': 'No active searches.'}]})
        invalid = await registry.invoke('start_search', {'path': str(self.data), 'pattern': 'x', 'extra': True})
        self.assertTrue(invalid['isError'])

    async def test_unsafe_result_inode_refuses_restart_without_repair(self):
        self.file('a.txt', 'needle\n')
        identity = await self.start(searchType='content', contextLines=0)
        await self.finish(identity)
        await asyncio.to_thread(self.manager.close)
        path = self.base / 'state' / identity / 'results.ndjson'
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            SearchManager(self.base / 'state', self.config)
        self.assertEqual(path.stat().st_mode & 0o777, 0o666)

    async def test_changed_result_bytes_refuse_restart_even_when_json_and_row_count_still_valid(self):
        self.file('a.txt', 'needle\n')
        identity = await self.start(searchType='content', contextLines=0)
        await self.finish(identity)
        await asyncio.to_thread(self.manager.close)
        path = self.base / 'state' / identity / 'results.ndjson'
        path.write_bytes(path.read_bytes().replace(b'needle', b'forged'))
        with self.assertRaisesRegex(ValueError, 'digest changed'):
            SearchManager(self.base / 'state', self.config)

    async def test_replaced_state_root_refuses_new_dispatch_and_history_adoption(self):
        original = self.base / 'state'
        original.rename(self.base / 'moved-state')
        original.mkdir(mode=0o700)
        with mock.patch('dc_compat.searches.subprocess.Popen', side_effect=AssertionError('must not spawn')):
            result = await self.manager.invoke('start_search', {'path': str(self.data), 'pattern': 'x'})
        self.assertTrue(result['isError'])
        self.assertIn('identity changed', result['content'][0]['text'])

    async def test_invalid_rg_regex_keeps_original_exit_two_incomplete_semantics(self):
        self.file('a.txt', 'needle\n')
        identity = await self.start(searchType='content', pattern='[', contextLines=0)
        self.assertEqual(await self.finish(identity), [])
        value = self.manager.sessions[identity].metadata
        self.assertTrue(value.get('wasIncomplete'))
        self.assertFalse(value['isError'])
        self.assertIn('Results may be incomplete', await self.page(identity))

    async def test_numeric_offsets_preserve_js_slice_behavior_without_extra_integer_restrictions(self):
        self.file('a.txt', ''.join(f'needle{i}\n' for i in range(6)))
        identity = await self.start(searchType='content', pattern='needle[0-9]+', contextLines=0)
        await self.finish(identity)
        self.assertEqual((await self.page(identity, offset=-0.5, length=0)).count('📄 '), 6)
        self.assertEqual((await self.page(identity, offset=1.5, length=2.5)).count('📄 '), 3)

    async def test_unknown_session_and_disallowed_path_are_tool_errors(self):
        result = await self.manager.invoke('get_more_search_results', {'sessionId': 'missing'})
        self.assertTrue(result['isError'])
        result = await self.manager.invoke('stop_search', {'sessionId': 'missing'})
        self.assertFalse(result.get('isError'))
        result = await self.manager.invoke('start_search', {'path': '/etc', 'pattern': 'x'})
        self.assertTrue(result['isError'])


class ArgumentTests(unittest.TestCase):
    def options(self, **extra):
        return {'rootPath': '/fixture', 'pattern': 'x', 'searchType': 'files', 'filePattern': '',
                'ignoreCase': True, 'includeHidden': False, 'contextLines': 5,
                'literalSearch': False, 'earlyTermination': True, **extra}

    def test_literal_context_hidden_case_max_and_content_pattern_termination(self):
        options = self.options(searchType='content', pattern='-needle', filePattern='*.py|!secret.py',
                               literalSearch=True, includeHidden=True, maxResults=3)
        self.assertEqual(build_rg_args(options), ['--json', '--line-number', '-F', '-C', '5', '-i',
            '--hidden', '-m', '3', '-g', '*.py', '-g', '!secret.py', '--', '-needle', '/fixture'])

    def test_file_fuzzy_glob_exact_and_zero_have_no_extra_limits(self):
        self.assertEqual(build_rg_args(self.options(maxResults=0)), ['--files', '--iglob', '*x*', '/fixture'])
        self.assertEqual(build_rg_args(self.options(pattern='config.json', ignoreCase=False)),
                         ['--files', '--glob', 'config.json', '/fixture'])
        self.assertEqual(build_rg_args(self.options(pattern='{a,b}.ts')), ['--files', '--iglob', '{a,b}.ts', '/fixture'])

    def test_json_parser_preserves_first_submatch_and_context_trimming(self):
        row = parse_rg_line(json.dumps({'type': 'match', 'data': {'path': {'text': 'p'}, 'line_number': 2,
            'lines': {'text': 'needle x needle\n'}, 'submatches': [{'match': {'text': 'needle'}}]}}), 'content')
        self.assertEqual(row, ({'file': 'p', 'line': 2, 'match': 'needle', 'type': 'content'}, False))


if __name__ == '__main__':
    unittest.main()
