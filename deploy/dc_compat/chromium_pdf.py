# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Local Chrome PDF renderer with an ephemeral profile and direct CDP only.

No running browser is discovered or attached. Markdown stays on this machine;
only resource URLs expressly present in the document can make asset requests.
Puppeteer PDFOptions are translated explicitly; unsupported options refuse.
"""
from __future__ import annotations
import base64
import html
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time
import urllib.parse

PDF_KEYS = frozenset(('scale', 'displayHeaderFooter', 'headerTemplate', 'footerTemplate',
    'printBackground', 'landscape', 'pageRanges', 'format', 'width', 'height',
    'preferCSSPageSize', 'margin', 'path', 'omitBackground', 'tagged', 'outline',
    'timeout', 'waitForFonts'))
TOP_KEYS = frozenset(('pdf_options', 'basedir', 'stylesheet', 'stylesheet_encoding',
    'css', 'document_title', 'body_class', 'page_media_type', 'launch_options'))
FORMATS = {'letter': (8.5, 11), 'legal': (8.5, 14), 'tabloid': (11, 17), 'ledger': (17, 11),
    'a0': (33.1102, 46.811), 'a1': (23.3858, 33.1102), 'a2': (16.5354, 23.3858),
    'a3': (11.6929, 16.5354), 'a4': (8.2677, 11.6929), 'a5': (5.8268, 8.2677), 'a6': (4.1339, 5.8268)}
DEFAULT_MARGIN = {'top': '30mm', 'right': '40mm', 'bottom': '30mm', 'left': '20mm'}
# Independent CSS matching the established Markdown document conventions.
DEFAULT_CSS = '''*{box-sizing:border-box}html{font-size:100%}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;line-height:1.6;font-size:.6875em;color:#111;margin:0}body>:first-child{padding-top:0;margin-top:0}body>:last-child{padding-bottom:0;margin-bottom:0}h1,h2,h3,h4,h5,h6{margin:0;padding:.5em 0 .25em}h5,h6{padding:0}h5{font-size:1em}h6{font-size:.875em;text-transform:uppercase}p{margin:.25em 0 1em}blockquote{margin:.5em 0 1em;padding-left:.5em;padding-right:1em;border-left:4px solid gainsboro;font-style:italic}ul,ol{margin:0 0 0 1em;padding:0 1.5em .5em}pre{white-space:pre-wrap}code{background:#f8f8f8;padding:.1em .375em;border:1px solid #f8f8f8;border-radius:.25em;font-family:monospace;font-size:1.2em}pre code{display:block;padding:.5em}.page-break{page-break-after:always}img{max-width:100%;margin:1em 0}table{border-spacing:0;border-collapse:collapse;display:block;margin:0 0 1em;width:100%;overflow:auto}th,td{padding:.5em 1em;border:1px solid gainsboro}th{font-weight:600}tr{background:white;border-top:1px solid gainsboro}tr:nth-child(2n){background:whitesmoke}'''


def _number(value, name, low=None, high=None):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(name + ' must be a finite number')
    if low is not None and value < low or high is not None and value > high:
        raise ValueError(name + ' is outside the supported range')
    return value


def _inches(value, name):
    if type(value) in (int, float): return _number(value, name, 0) / 96
    if not isinstance(value, str): raise ValueError(name + ' must be a number or CSS print length')
    match = re.fullmatch(r'\s*([+]?(?:\d+(?:\.\d*)?|\.\d+))\s*(px|in|cm|mm)?\s*', value.lower())
    if not match: raise ValueError(name + ' must use px, in, cm, or mm')
    return float(match[1]) * {'px': 1 / 96, 'in': 1, 'cm': 1 / 2.54, 'mm': 1 / 25.4}[match[2] or 'px']


def parse_options(options):
    if options is None: options = {}
    if not isinstance(options, dict): raise ValueError('PDF options must be an object')
    unknown = set(options) - TOP_KEYS - PDF_KEYS
    if unknown: raise ValueError('Unsupported Markdown/PDF options: ' + ', '.join(sorted(unknown)))
    top = {key: value for key, value in options.items() if key in TOP_KEYS}
    pdf = dict(printBackground=True, format='a4', margin=DEFAULT_MARGIN.copy())
    # Keep the previous direct-PDFOptions form in addition to md-to-pdf's
    # canonical options.pdf_options envelope.
    pdf.update({key: value for key, value in options.items() if key in PDF_KEYS})
    nested = options.get('pdf_options', {})
    if not isinstance(nested, dict): raise ValueError('pdf_options must be an object')
    if set(nested) - PDF_KEYS:
        raise ValueError('Unsupported Puppeteer PDFOptions: ' + ', '.join(sorted(set(nested) - PDF_KEYS)))
    pdf.update(nested)
    launch = top.get('launch_options', {})
    if not isinstance(launch, dict): raise ValueError('launch_options must be an object')
    # Arbitrary executable/profile/extension/remote-debugging overrides could
    # attach to a user browser. Refuse instead of silently ignoring them.
    if set(launch) - {'headless', 'timeout'}:
        raise ValueError('Unsupported private Chrome launch_options: ' + ', '.join(sorted(set(launch) - {'headless', 'timeout'})))
    if launch.get('headless', True) not in (True, 'new', 'shell'):
        raise ValueError('PDF rendering requires a private headless browser')
    for name in ('printBackground', 'landscape', 'preferCSSPageSize', 'displayHeaderFooter',
                 'omitBackground', 'tagged', 'outline', 'waitForFonts'):
        if name in pdf and type(pdf[name]) is not bool: raise ValueError(name + ' must be boolean')
    for name in ('headerTemplate', 'footerTemplate', 'pageRanges', 'path'):
        if name in pdf and not isinstance(pdf[name], str): raise ValueError(name + ' must be a string')
    _number(pdf.get('scale', 1), 'scale', .1, 2)
    _number(pdf.get('timeout', 30000), 'timeout', 0)
    _number(launch.get('timeout', 30000), 'launch_options.timeout', 0)
    if (pdf.get('headerTemplate') or pdf.get('footerTemplate')) and 'displayHeaderFooter' not in pdf:
        pdf['displayHeaderFooter'] = True
    if pdf.get('format') is not None:
        if not isinstance(pdf['format'], str) or pdf['format'].lower() not in FORMATS:
            raise ValueError('Unknown paper format')
        width, height = FORMATS[pdf['format'].lower()]
    else:
        width = _inches(pdf.get('width', '8.5in'), 'width')
        height = _inches(pdf.get('height', '11in'), 'height')
    margin = pdf.get('margin', {})
    if isinstance(margin, str):
        values = margin.split()
        if not 1 <= len(values) <= 4: raise ValueError('margin must contain one to four CSS lengths')
        values = ([values[0]] * 4 if len(values) == 1 else [values[0], values[1], values[0], values[1]] if len(values) == 2
                  else [values[0], values[1], values[2], values[1]] if len(values) == 3 else values)
        margin = dict(zip(('top', 'right', 'bottom', 'left'), values))
    if not isinstance(margin, dict) or set(margin) - {'top', 'right', 'bottom', 'left'}:
        raise ValueError('margin must be a CSS shorthand or top/right/bottom/left object')
    parameters = dict(landscape=pdf.get('landscape', False), displayHeaderFooter=pdf.get('displayHeaderFooter', False),
        printBackground=pdf.get('printBackground', True), scale=pdf.get('scale', 1), paperWidth=width, paperHeight=height,
        pageRanges=pdf.get('pageRanges', ''), headerTemplate=pdf.get('headerTemplate', ''),
        footerTemplate=pdf.get('footerTemplate', ''), preferCSSPageSize=pdf.get('preferCSSPageSize', False),
        generateTaggedPDF=pdf.get('tagged', True), generateDocumentOutline=pdf.get('outline', False), transferMode='ReturnAsBase64')
    for side in ('top', 'right', 'bottom', 'left'):
        parameters['margin' + side.title()] = _inches(margin.get(side, 0), 'margin.' + side)
    return top, pdf, parameters


def _resource_path(value, request, base=None):
    path = Path(value).expanduser()
    if not path.is_absolute(): path = Path(base or request['workspace']) / path
    path = path.resolve()
    roots = []
    for raw in request.get('allowed_directories') or ['/']:
        root = Path(raw).expanduser()
        roots.append((root if root.is_absolute() else Path(request['workspace']) / root).resolve())
    if not any(path == root or root in path.parents for root in roots):
        raise ValueError('PDF resource path is outside allowed directories')
    return path


class _CDP:
    def __init__(self, connection, timeout, resource_check):
        self.connection, self.timeout, self.resource_check = connection, timeout, resource_check
        self.serial, self.responses, self.session = 0, {}, None

    def send(self, method, parameters=None):
        self.serial += 1
        request = {'id': self.serial, 'method': method, 'params': parameters or {}}
        if self.session: request['sessionId'] = self.session
        self.connection.send(json.dumps(request))
        return self.serial

    def call(self, method, parameters=None):
        identity = self.send(method, parameters)
        while identity not in self.responses:
            if self.timeout is not None:
                remaining = self.timeout - time.monotonic()
                if remaining <= 0: raise TimeoutError('Private Chrome PDF rendering timed out')
                self.connection.settimeout(remaining)
            response = json.loads(self.connection.recv())
            if response.get('method') == 'Fetch.requestPaused':
                value = response['params']
                try:
                    self.resource_check(value['request']['url'])
                    self.send('Fetch.continueRequest', {'requestId': value['requestId']})
                except ValueError:
                    self.send('Fetch.failRequest', {'requestId': value['requestId'], 'errorReason': 'AccessDenied'})
            elif 'id' in response:
                self.responses[response['id']] = response
        result = self.responses.pop(identity)
        if 'error' in result: raise ValueError('Chrome PDF request refused: ' + result['error'].get('message', 'protocol error'))
        return result.get('result', {})


def render_markdown(markdown, options, request):
    import markdown as md
    import websocket
    top, pdf, parameters = parse_options(options)
    base = _resource_path(top.get('basedir', request['workspace']), request)
    if not base.is_dir(): raise ValueError('PDF basedir must be a directory')
    styles = top.get('stylesheet', [])
    if isinstance(styles, str): styles = [styles]
    if not isinstance(styles, list) or any(not isinstance(value, str) for value in styles):
        raise ValueError('stylesheet must be a path/URL or array of paths/URLs')
    css, links = DEFAULT_CSS, []
    for value in styles:
        if urllib.parse.urlsplit(value).scheme in ('http', 'https'):
            links.append('<link rel="stylesheet" href="' + html.escape(value, quote=True) + '">')
        else:
            stylesheet = _resource_path(value, request, base)
            css += '\n' + stylesheet.read_text(encoding=top.get('stylesheet_encoding', 'utf-8'))
    if not isinstance(top.get('css', ''), str): raise ValueError('css must be a string')
    css += '\n' + top.get('css', '')
    classes = top.get('body_class', [])
    if isinstance(classes, str): classes = [classes]
    if not isinstance(classes, list) or any(not isinstance(value, str) for value in classes):
        raise ValueError('body_class must be a string or array')
    media = top.get('page_media_type', 'screen')
    if media not in ('screen', 'print', None): raise ValueError('page_media_type must be screen, print, or null')
    body = md.markdown(markdown, extensions=['extra', 'tables', 'fenced_code'])
    document = ('<!doctype html><html><head><meta charset="utf-8"><base href="' + html.escape(base.as_uri() + '/', quote=True)
        + '"><title>' + html.escape(str(top.get('document_title', ''))) + '</title>' + ''.join(links)
        + '<style>' + css + '</style></head><body class="' + html.escape(' '.join(classes), quote=True) + '">' + body + '</body></html>')
    denied = []
    def resource_check(url):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme == 'file':
            path = Path(urllib.parse.unquote(parsed.path)).resolve()
            if path != input_path:
                try: _resource_path(path, request)
                except ValueError:
                    denied.append(url); raise
        elif parsed.scheme not in ('http', 'https', 'data', 'about', 'blob'):
            denied.append(url); raise ValueError('PDF resource scheme is not permitted')
    # Catch ordinary local references even if Chrome decides not to fetch a
    # broken resource. Nested stylesheet/image resources also pass CDP Fetch.
    class ResourceReferences(HTMLParser):
        def __init__(self): super().__init__(); self.values = []
        def handle_starttag(self, tag, attributes):
            values = dict(attributes)
            # Hyperlinks are output metadata, not permission to read a file.
            # Check only fetchable resources here; CDP checks actual requests.
            keys = ['src', 'poster']
            if tag == 'link' and values.get('rel', '').lower() in ('stylesheet', 'icon'): keys.append('href')
            if tag in ('image', 'use'): keys.extend(('href', 'xlink:href'))
            if tag == 'object': keys.append('data')
            self.values.extend(values[key] for key in keys if values.get(key))
    references = ResourceReferences(); references.feed(document)
    references.values.extend(re.findall(r'''url\(\s*["']?([^\)"']+)''', document, re.I))
    for value in references.values:
        url = urllib.parse.urljoin(base.as_uri() + '/', value)
        if urllib.parse.urlsplit(url).scheme == 'file': _resource_path(urllib.parse.unquote(urllib.parse.urlsplit(url).path), request)
    extra_path = _resource_path(pdf['path'], request) if pdf.get('path') else None
    chrome = Path('/usr/bin/google-chrome')
    if not chrome.is_file(): raise ValueError('Independent system Google Chrome is unavailable')
    with tempfile.TemporaryDirectory(prefix='hepta-private-pdf-') as directory:
        private = Path(directory)
        profile = private / 'profile'; profile.mkdir(mode=0o700)
        input_path = private / 'document.html'; input_path.write_text(document, encoding='utf-8'); input_path.chmod(0o600)
        flags = [str(chrome), '--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
            '--user-data-dir=' + str(profile), '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
            '--disable-component-update', '--disable-sync', '--disable-default-apps', '--metrics-recording-only',
            '--disable-extensions', '--disable-dev-shm-usage', '--password-store=basic', '--use-mock-keychain',
            '--allow-file-access-from-files', 'about:blank']
        with (private / 'chrome.log').open('wb') as log:
            process = subprocess.Popen(flags, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            connection = None
            try:
                launch_ms = top.get('launch_options', {}).get('timeout', 30000)
                launch_deadline = time.monotonic() + launch_ms / 1000 if launch_ms else None
                while not (profile / 'DevToolsActivePort').is_file():
                    if process.poll() is not None:
                        raise ValueError('Private Chrome exited before PDF rendering: ' + (private / 'chrome.log').read_text(errors='replace')[-1500:])
                    if launch_deadline is not None and time.monotonic() >= launch_deadline: raise TimeoutError('Private Chrome launch timed out')
                    time.sleep(.02)
                port, path = (profile / 'DevToolsActivePort').read_text().splitlines()[:2]
                connection = websocket.create_connection('ws://127.0.0.1:' + port + path, timeout=30, suppress_origin=True,
                                                         http_proxy_host=None, http_no_proxy=['127.0.0.1'])
                timeout = pdf.get('timeout', 30000)
                cdp = _CDP(connection, time.monotonic() + timeout / 1000 if timeout else None, resource_check)
                target = cdp.call('Target.createTarget', {'url': 'about:blank'})['targetId']
                cdp.session = cdp.call('Target.attachToTarget', {'targetId': target, 'flatten': True})['sessionId']
                cdp.call('Page.enable')
                cdp.call('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]})
                # Document scripts are never needed to print Markdown and must
                # not send its source to an unrelated network endpoint.
                cdp.call('Emulation.setScriptExecutionDisabled', {'value': True})
                cdp.call('Emulation.setEmulatedMedia', {'media': media or ''})
                if pdf.get('omitBackground'):
                    cdp.call('Emulation.setDefaultBackgroundColorOverride', {'color': {'r': 0, 'g': 0, 'b': 0, 'a': 0}})
                navigation = cdp.call('Page.navigate', {'url': input_path.as_uri()})
                if navigation.get('errorText'): raise ValueError('Private document navigation failed: ' + navigation['errorText'])
                while True:
                    state = cdp.call('Runtime.evaluate', {'expression': '({url:document.URL,state:document.readyState})', 'returnByValue': True})
                    value = state.get('result', {}).get('value', {})
                    if value.get('url') == input_path.as_uri() and value.get('state') == 'complete': break
                    time.sleep(.01)
                expression = "Promise.all([...document.images].map(i=>i.complete?Promise.resolve():new Promise(r=>{i.onload=r;i.onerror=r})))"
                if pdf.get('waitForFonts', True): expression += '.then(()=>document.fonts.ready)'
                ready = cdp.call('Runtime.evaluate', {'expression': expression, 'awaitPromise': True, 'returnByValue': False})
                if ready.get('exceptionDetails'): raise ValueError('Chrome document assets could not become ready')
                if denied: raise ValueError('PDF resource path is outside allowed directories; output was not modified')
                encoded = cdp.call('Page.printToPDF', parameters)
                if denied: raise ValueError('PDF resource path is outside allowed directories; output was not modified')
                result = base64.b64decode(encoded['data'], validate=True)
                if not result.startswith(b'%PDF'): raise ValueError('Private Chrome returned an invalid PDF')
                cdp.session = None
                cdp.call('Browser.close')
                process.wait(timeout=10)
            finally:
                if connection is not None: connection.close()
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
        if extra_path is not None:
            descriptor, staging = tempfile.mkstemp(prefix='.hepta-pdf-', dir=extra_path.parent)
            try:
                if extra_path.exists(): os.fchmod(descriptor, stat.S_IMODE(extra_path.stat().st_mode))
                with os.fdopen(descriptor, 'wb') as output:
                    output.write(result); output.flush(); os.fsync(output.fileno())
                os.replace(staging, extra_path)
            finally:
                Path(staging).unlink(missing_ok=True)
        return result
