# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fresh private Chrome only; inspect actual PDF geometry/text/rendered pixels."""
import asyncio
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.chromium_pdf import parse_options, render_markdown, PDF_KEYS
from dc_compat.filesystem import FileManager

DOCUMENT_PYTHON = '/home/qian-qi/.local/lib/hepta-runtime/document-env-formats-20261006/bin/python'


class Config:
    def __init__(self, root): self.workspace, self.document_python = root, DOCUMENT_PYTHON
    def get(self, key, default=None):
        return [str(self.workspace)] if key == 'allowedDirectories' else default
    def resolve_path(self, raw):
        path = Path(raw)
        path = (path if path.is_absolute() else self.workspace / path).resolve()
        if path != self.workspace and self.workspace not in path.parents: raise ValueError('outside fixture')
        return path


class ChromiumPDF(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hepta-pdf-options-')
        self.root = Path(self.temporary.name)
        self.manager = FileManager(Config(self.root))

    async def asyncTearDown(self): self.temporary.cleanup()

    async def write(self, name, content, options=None, **extra):
        args = {'path': name, 'content': content, **extra}
        if options is not None: args['options'] = options
        result = await self.manager.invoke('write_pdf', args)
        self.assertFalse(result.get('isError'), result)
        return self.root / extra.get('outputPath', name)

    def read(self, path):
        from pypdf import PdfReader
        return PdfReader(path)

    def pixels(self, path):
        from PIL import Image
        prefix = self.root / (path.stem + '-pixels')
        subprocess.run(['/usr/bin/pdftocairo', '-png', '-transp', '-singlefile', '-r', '72', str(path), str(prefix)], check=True, capture_output=True)
        return Image.open(str(prefix) + '.png').convert('RGBA')

    def test_explicit_mapping_every_pdfoption_and_unknown_refuses_before_browser(self):
        options = dict(scale=.5, displayHeaderFooter=True, headerTemplate='<b>H</b>', footerTemplate='<b>F</b>',
            printBackground=False, landscape=True, pageRanges='2-3', format=None, width='210mm', height=960,
            preferCSSPageSize=True, margin='1cm 2cm 3cm 4cm', path='extra.pdf', omitBackground=True,
            tagged=False, outline=True, timeout=0, waitForFonts=False)
        self.assertEqual(set(options), PDF_KEYS)
        _, pdf, mapped = parse_options({'pdf_options': options})
        self.assertAlmostEqual(mapped['paperWidth'], 210 / 25.4)
        self.assertEqual(mapped['paperHeight'], 10)
        self.assertAlmostEqual(mapped['marginLeft'], 4 / 2.54)
        self.assertTrue(mapped['generateDocumentOutline'])
        self.assertFalse(mapped['generateTaggedPDF'])
        self.assertEqual(pdf['timeout'], 0)
        for value in ({'pdf_options': {'unknownPrintOption': True}}, {'unknownMarkdownOption': 1},
                      {'launch_options': {'userDataDir': '/never'}}, {'launch_options': {'executablePath': '/never'}},
                      {'script': ['never.js']}):
            with mock.patch('dc_compat.chromium_pdf.subprocess.Popen', side_effect=AssertionError('must refuse before spawn')):
                with self.assertRaises(ValueError): parse_options(value)

    async def test_letter_landscape_margins_headerfooter_tagged_outline_and_extra_path(self):
        target = await self.write('landscape.pdf', '# Outline title\n\nBODY-CONTENT', {'document_title': 'Fixture title',
            'pdf_options': {'format': 'Letter', 'landscape': True, 'margin': {'top': '1in', 'bottom': '1in', 'left': '1in', 'right': '1in'},
                'headerTemplate': '<div style="font-size:12px">HEADER-PROOF</div>',
                'footerTemplate': '<div style="font-size:12px">FOOTER <span class="pageNumber"></span>/<span class="totalPages"></span></div>',
                'tagged': True, 'outline': True, 'path': 'extra-copy.pdf'}})
        reader = self.read(target)
        self.assertEqual(len(reader.pages), 1)
        self.assertAlmostEqual(float(reader.pages[0].mediabox.width), 792, delta=1)
        self.assertAlmostEqual(float(reader.pages[0].mediabox.height), 612, delta=1)
        text = reader.pages[0].extract_text()
        self.assertIn('HEADER-PROOF', text); self.assertIn('FOOTER 1/1', text); self.assertIn('BODY-CONTENT', text)
        self.assertEqual(reader.metadata.title, 'Fixture title')
        self.assertTrue(reader.trailer['/Root'].get('/MarkInfo', {}).get('/Marked'))
        self.assertTrue(reader.outline)
        self.assertEqual(target.read_bytes(), (self.root / 'extra-copy.pdf').read_bytes())

    async def test_page_ranges_print_only_selected_original_page(self):
        markdown = '# PAGE-ONE\n<div class="page-break"></div>\n\n# PAGE-TWO\n<div class="page-break"></div>\n\n# PAGE-THREE'
        path = await self.write('range.pdf', markdown, {'pdf_options': {'pageRanges': '2'}})
        reader = self.read(path)
        self.assertEqual(len(reader.pages), 1)
        text = reader.pages[0].extract_text()
        self.assertIn('PAGE-TWO', text); self.assertNotIn('PAGE-ONE', text); self.assertNotIn('PAGE-THREE', text)

    async def test_css_page_size_and_custom_numeric_and_unit_dimensions(self):
        css = '@page {size:200px 300px; margin:0}'
        preferred = await self.write('css.pdf', '# CSS-PAGE', {'css': css, 'pdf_options': {'preferCSSPageSize': True}})
        page = self.read(preferred).pages[0]
        self.assertAlmostEqual(float(page.mediabox.width), 150, delta=1)
        self.assertAlmostEqual(float(page.mediabox.height), 225, delta=1)
        custom = await self.write('custom.pdf', 'CUSTOM', {'pdf_options': {'format': None, 'width': 384, 'height': '5in', 'margin': '0'}})
        page = self.read(custom).pages[0]
        self.assertAlmostEqual(float(page.mediabox.width), 288, delta=1)
        self.assertAlmostEqual(float(page.mediabox.height), 360, delta=1)
        normal = await self.write('a4.pdf', 'A4', {'css': css})
        self.assertAlmostEqual(float(self.read(normal).pages[0].mediabox.width), 595.27, delta=1)

    async def test_background_scale_and_omitbackground_affect_real_rendered_pixels(self):
        content = '<div style="position:fixed;left:0;top:0;width:200px;height:200px;background:rgb(255,0,0)"></div>'
        base = {'format': None, 'width': '400px', 'height': '400px', 'margin': '0'}
        normal = await self.write('red.pdf', content, {'pdf_options': dict(base, printBackground=True)})
        no_background = await self.write('no-background.pdf', content, {'pdf_options': dict(base, printBackground=False)})
        scaled = await self.write('scaled.pdf', content, {'pdf_options': dict(base, printBackground=True, scale=.5)})
        transparent = await self.write('transparent.pdf', '', {'pdf_options': dict(base, omitBackground=True)})
        red, plain, small, clear = map(self.pixels, (normal, no_background, scaled, transparent))
        self.assertEqual(red.getpixel((100, 100))[:3], (255, 0, 0))
        self.assertNotEqual(plain.getpixel((100, 100))[:3], (255, 0, 0))
        self.assertNotEqual(small.getpixel((100, 100))[:3], (255, 0, 0))
        self.assertEqual(clear.getpixel((100, 100))[3], 0)

    async def test_svg_local_image_stylesheet_body_class_media_and_private_profiles(self):
        from PIL import Image
        Image.new('RGB', (10, 10), 'green').save(self.root / 'owned.png')
        (self.root / 'owned.css').write_text('.fixture{color:blue}@media print{.screen-only{display:none}}')
        content = '![local](owned.png)\n\n<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40"><rect width="40" height="40" fill="red"/></svg>\n\n<div class="screen-only">SCREEN-CONTENT</div>'
        path = await self.write('assets.pdf', content, {'stylesheet': 'owned.css', 'body_class': ['fixture'],
                                                     'page_media_type': 'screen'})
        reader = self.read(path)
        self.assertTrue(reader.pages[0].images)
        self.assertIn('SCREEN-CONTENT', reader.pages[0].extract_text())
        self.assertIn(b'1 0 0 RG', reader.pages[0].get_contents().get_data())

    async def test_private_chrome_launch_uses_only_new_profile_and_disposes_it(self):
        profiles = []
        original = subprocess.Popen
        def launch(command, *args, **kwargs):
            self.assertEqual(command[0], '/usr/bin/google-chrome')
            self.assertIn('--remote-debugging-port=0', command)
            self.assertIn('--remote-debugging-address=127.0.0.1', command)
            profile = Path(next(value.split('=', 1)[1] for value in command if value.startswith('--user-data-dir=')))
            self.assertTrue(profile.parent.name.startswith('hepta-private-pdf-'))
            self.assertEqual(profile.stat().st_mode & 0o777, 0o700)
            profiles.append(profile)
            return original(command, *args, **kwargs)
        with mock.patch('dc_compat.chromium_pdf.subprocess.Popen', side_effect=launch):
            result = await asyncio.to_thread(render_markdown, '# PRIVATE-PROFILE', {},
                {'workspace': str(self.root), 'allowed_directories': [str(self.root)]})
        self.assertTrue(result.startswith(b'%PDF'))
        self.assertEqual(len(profiles), 1)
        self.assertFalse(profiles[0].parent.exists())

    async def test_markdown_insert_inherits_original_page_dimensions_and_crop_margins(self):
        from pypdf import PdfWriter
        writer = PdfWriter(); page = writer.add_blank_page(width=400, height=500)
        page.cropbox.lower_left, page.cropbox.upper_right = (10, 20), (380, 460)
        source = self.root / 'original.pdf'
        with source.open('wb') as output: writer.write(output)
        original = source.read_bytes()
        path = await self.write('original.pdf', [{'type': 'insert', 'pageIndex': 1, 'markdown': '# INSERTED-LAYOUT'},
                                               {'type': 'delete', 'pageIndexes': [0]}], outputPath='inserted.pdf')
        reader = self.read(path)
        self.assertEqual(len(reader.pages), 1)
        # Chrome quantizes custom paper sizes to its print-device units, also
        # when called through Puppeteer (the source layout uses 4 decimals).
        self.assertAlmostEqual(float(reader.pages[0].mediabox.width), 400, delta=1.5)
        self.assertAlmostEqual(float(reader.pages[0].mediabox.height), 500, delta=1.5)
        self.assertIn('INSERTED-LAYOUT', reader.pages[0].extract_text())
        self.assertEqual(source.read_bytes(), original)

    async def test_unknown_options_and_invalid_ranges_preserve_existing_output(self):
        original = await self.write('unchanged.pdf', '# ORIGINAL')
        before = original.read_bytes()
        for options in ({'pdf_options': {'madeUp': True}}, {'pdf_options': {'pageRanges': '9999'}},
                        {'launch_options': {'userDataDir': '/never-attach'}}):
            result = await self.manager.invoke('write_pdf', {'path': 'unchanged.pdf', 'content': '# WRONG', 'options': options})
            self.assertTrue(result.get('isError'), result)
            self.assertEqual(original.read_bytes(), before)

    async def test_hyperlink_outside_resource_roots_does_not_read_or_reject_link_metadata(self):
        # A file hyperlink is retained as document metadata; it must not be
        # confused with an image/font/stylesheet which actually reads bytes.
        with tempfile.TemporaryDirectory(prefix='hepta-pdf-link-only-') as directory:
            outside = Path(directory) / 'never-read.txt'
            outside.write_text('SECRET-RESOURCE-NOT-READ')
            path = await self.write('links.pdf', '[Reference link](' + outside.as_uri() + ')')
            reader = self.read(path)
            self.assertIn('Reference link', reader.pages[0].extract_text())
            self.assertNotIn('SECRET-RESOURCE-NOT-READ', reader.pages[0].extract_text())
            self.assertTrue(reader.pages[0].get('/Annots'))


if __name__ == '__main__': unittest.main()
