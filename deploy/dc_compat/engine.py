# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent local computer operator; no DC executable, service or import."""
from __future__ import annotations
import asyncio
import copy
import datetime
import getpass
import hashlib
import json
import os
import pathlib
import platform
import secrets
import socket
import time
import webbrowser
from .configuration import CompatConfig
from .journal import CallJournal, encode
from .processes import ProcessManager
from .registry import ToolError, ToolRegistry, text_result


def extension(name, description, properties, required=(), read_only=True):
    return {'name': name, 'description': description,
        'inputSchema': {'type': 'object', 'properties': properties, 'required': list(required), 'additionalProperties': False},
        'annotations': {'title': name.replace('_', ' ').title(), 'readOnlyHint': read_only}}


EXTRA_TOOLS = [extension('hepta_call_result_page',
    'Read complete immutable original tool-result JSON by independent byte offsets, base64 and SHA256. Never reruns an action.',
    {'call_id': {'type': 'string'}, 'offset': {'type': 'integer', 'minimum': 0},
     'limit': {'type': 'integer', 'minimum': 1, 'maximum': 1048576}}, ['call_id'])]

PROMPTS = {
    'onb2_01': 'Inspect the Downloads directory, propose an organization, then move only the files the user has authorized. Preserve names and report conflicts.',
    'onb2_02': 'Inspect the requested repository, explain its architecture and entry points, then validate conclusions against its source and tests.',
    'onb2_03': 'Create a knowledge base from the files the user selected. Preserve original material and link every summary to its source.',
    'onb2_04': 'Inspect the selected data file, determine its schema, calculate useful summaries and clearly distinguish missing values from zero.',
    'onb2_05': 'Inspect system resources and running processes using read-only tools. Explain findings before any change or termination.'}


class Operator:
    def __init__(self, state_dir, workspace, *, document_python=None, initial=None,
                 synchronous_wait=1.0, enable_computer=True, include_providers=True):
        self.state_dir = pathlib.Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.config = CompatConfig(self.state_dir / 'configuration', workspace,
                                   document_python=document_python, initial=initial)
        self.journal = CallJournal(self.state_dir / 'journal')
        self.processes = ProcessManager(self.state_dir / 'processes', self.config.workspace, config=self.config)
        self.providers = [self.processes]
        catalog = json.loads((pathlib.Path(__file__).parent / 'catalog.json').read_bytes())
        definitions = copy.deepcopy(catalog['tools'])
        definitions += [{k: copy.deepcopy(value) for k, value in row.items() if k in ('name', 'description', 'inputSchema', 'annotations')}
                        for row in catalog['cloud_application_tools']]
        definitions += copy.deepcopy(EXTRA_TOOLS)
        self.computer = self.windows = None
        if include_providers:
            from .filesystem import FileManager
            from .searches import SearchManager
            self.providers += [FileManager(self.config, document_python=self.config.document_python),
                               SearchManager(self.state_dir / 'searches', self.config)]
        if enable_computer:
            from .computer import ComputerManager, COMPUTER_TOOLS
            self.computer = ComputerManager(self.config.snapshot())
            self.providers.append(self.computer)
            definitions += copy.deepcopy(COMPUTER_TOOLS)
            if self.config.get('windowBackend') == 'gnome-extension':
                from .gnome_window_provider import GnomeWindowManager, GNOME_WINDOW_TOOLS
                self.windows = GnomeWindowManager({'token_path': self.config.get('window_token_path'),
                    'profile_id': self.config.get('profile_id'), 'dbus_address': self.config.get('dbus_address')})
                self.providers.append(self.windows)
                definitions = [row for row in definitions if row['name'] != 'computer_window'] + copy.deepcopy(GNOME_WINDOW_TOOLS)
        self.registry = ToolRegistry(definitions)
        for provider in self.providers:
            if provider is self.computer and self.windows is not None:
                self.registry.add_handler(provider.tool_names - {'computer_window', 'computer_capabilities'}, provider.invoke)
            else:
                self.registry.add(provider)
        if self.windows is not None:
            self.registry.add_handler({'computer_capabilities'}, self._computer_capabilities)
        owned = {'get_config', 'set_config_value', 'get_recent_tool_calls', 'get_usage_stats',
                 'get_tool_result', 'list_remote_tool_calls', 'list_devices', 'who_am_i', 'ping',
                 'shutdown', 'give_feedback_to_desktop_commander', 'get_prompts', 'hepta_call_result_page'}
        self.registry.add_handler(owned, self._control)
        self.device_id = 'hepta-local-' + hashlib.sha256((str(os.getuid()) + '\0' + socket.gethostname()).encode()).hexdigest()[:24]
        self.synchronous_wait = synchronous_wait
        self.tasks = {}
        self.current_client = {}
        self.shutdown_requested = asyncio.Event()
        self._closing = False
        self._admission_paused = False
        self._close_task = None

    async def _computer_capabilities(self, name, arguments):
        base = await self.computer.invoke(name, arguments)
        if base.get('isError'):
            return base
        value = base['structuredContent']['result']
        windows = await self.windows.capabilities()
        value['gnome_window_bridge'] = windows
        value.setdefault('features', {}).update({key: bool(windows.get('available') and windows.get('features', {}).get(key))
            for key in ('window_list', 'window_focus')})
        if windows.get('available'):
            value['limitations'] = [line for line in value.get('limitations', []) if 'global window' not in line]
        return text_result(json.dumps(value, ensure_ascii=False), structured={'result': value})

    async def _control(self, name, arguments):
        if name == 'get_config':
            view = self.config.describe(self.current_client, self.journal.clients())
            view['config']['usageStats'] = self.journal.stats()
            return text_result('Current configuration:\n' + json.dumps(view['config'], ensure_ascii=False, indent=2), structured=view)
        if name == 'set_config_value':
            self.config.set(arguments['key'], arguments['value'])
            return text_result('Successfully updated ' + arguments['key'])
        if name == 'get_recent_tool_calls':
            rows = self.journal.recent(arguments.get('maxResults', 50), arguments.get('toolName'), arguments.get('since'))
            return text_result(f'Tool Call History ({len(rows)} results)\n\n' + json.dumps(rows, ensure_ascii=False, indent=2))
        if name == 'get_usage_stats':
            return text_result(json.dumps(self.journal.stats(), ensure_ascii=False, indent=2))
        if name == 'get_tool_result':
            return text_result(json.dumps(self.journal.result(arguments['call_id']), ensure_ascii=False))
        if name == 'hepta_call_result_page':
            return text_result(json.dumps(self.journal.page(arguments['call_id'], arguments.get('offset', 0), arguments.get('limit', 16384))))
        if name == 'list_remote_tool_calls':
            return text_result(json.dumps({'calls': self.journal.background(arguments.get('limit', 50)), 'provider': 'Hepta Runtime'}, ensure_ascii=False))
        if name == 'list_devices':
            return text_result(json.dumps({'provider': 'Hepta Runtime', 'devices': [{'id': self.device_id,
                'name': socket.gethostname(), 'online': True, 'platform': platform.system(),
                'capabilities': sorted(self.registry.implemented_tools)}],
                'device_management': 'This independent Hepta operator has no dependency on a DC account or device enrollment.'}))
        if name == 'who_am_i':
            return text_result(json.dumps({'provider': 'Hepta Runtime', 'user': getpass.getuser(),
                'uid': os.getuid(), 'device_id': self.device_id, 'usage': self.journal.stats(),
                'vendor_subscription': None, 'identity_scope': 'authenticated local operator; not a DC vendor account'}))
        if name in ('ping', 'shutdown'):
            if arguments.get('deviceId') not in (None, self.device_id, 'main', 'local'):
                raise ToolError('Unknown Hepta device; no action submitted')
            if name == 'ping':
                return text_result(json.dumps({'message': 'pong', 'deviceId': self.device_id,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'provider': 'Hepta Runtime'}))
            asyncio.get_running_loop().call_later(0.5, self.shutdown_requested.set)
            return text_result('Hepta agent shutdown scheduled. This does not shut down the computer or stop DC.')
        if name == 'give_feedback_to_desktop_commander':
            url = self.config.get('feedbackUrl', 'https://github.com/TrillionniumFoundation/hepta-runtime/issues')
            opened = await asyncio.to_thread(webbrowser.open, url)
            return text_result(json.dumps({'provider': 'Hepta Runtime', 'feedback_url': url, 'browser_opened': bool(opened)}))
        if name == 'get_prompts':
            identity = arguments['promptId']
            if identity not in PROMPTS:
                raise ToolError('Unknown onboarding prompt')
            return text_result(PROMPTS[identity])
        raise ToolError('Unimplemented control tool')

    async def _execute(self, identity, name, arguments):
        self.journal.executing(identity)
        try:
            result = await self.registry.invoke(name, arguments)
        except Exception as error:
            result = text_result('Operator action failed: ' + type(error).__name__ + '; do not replay an uncertain action', is_error=True)
        try:
            self.journal.complete(identity, result)
        except Exception:
            # The durable intent survives. Repeating the RPC must never issue a
            # second action even if the device filled its result disk.
            return text_result(json.dumps({'call_id': identity, 'status': 'unknown', 'automatic_retry': False,
                'reason': 'Result persistence unavailable after action submission'}), is_error=True)
        return result

    async def call(self, name, arguments, rpc_key):
        if self._closing:
            return text_result('Hepta operator is closing; no new action submitted', is_error=True)
        if self._admission_paused and name not in ('get_tool_result', 'hepta_call_result_page'):
            return text_result('Hepta owner is paused for maintenance; no new action submitted', is_error=True)
        # Validation is performed by the registry before a provider can act.
        row, reused = self.journal.begin(name, arguments, rpc_key)
        identity = row['call_id']
        if reused:
            result = self.journal.result(identity)
            if 'result' in result:
                return result['result']
            return text_result(json.dumps(result, ensure_ascii=False))
        task = asyncio.create_task(self._execute(identity, name, arguments))
        self.tasks[identity] = task
        task.add_done_callback(lambda _: self.tasks.pop(identity, None))
        finished, _ = await asyncio.wait({task}, timeout=self.synchronous_wait)
        if finished:
            result = task.result()
            # Preserve the immutable original in SQLite even when a direct
            # response must use a complete independently paged result handle.
            if len(encode(result)) > 8 * 1024 * 1024:
                self.journal.mark_background(identity)
                return text_result(json.dumps(self.journal.result(identity)))
            return result
        self.journal.mark_background(identity)
        return text_result(json.dumps({'call_id': identity, 'status': 'running', 'automatic_retry': False,
            'next_action': 'get_tool_result', 'provider': 'Hepta Runtime'}))

    async def close(self):
        if self._close_task is None:
            self._closing = True
            self._close_task = asyncio.create_task(self._close_owned_resources())
        await asyncio.shield(self._close_task)

    async def _close_owned_resources(self):
        self._closing = True
        # Cancelling asyncio.to_thread does not stop its OS operation. Keep
        # every ownership lock and the result journal until accepted work has
        # actually finished, then close the providers which own its children.
        if self.tasks:
            await asyncio.shield(asyncio.gather(*list(self.tasks.values()), return_exceptions=True))
        failures = []
        for provider in reversed(self.providers):
            close = getattr(provider, 'close', None)
            if close is not None:
                try:
                    if asyncio.iscoroutinefunction(close):
                        await close()
                    else:
                        await asyncio.to_thread(close)
                except Exception as error:
                    failures.append(error)
        # One revoked GUI connection must not skip cleanup of our own process
        # children, or leave the durable owner lock held by a live loop.
        for close in (self.journal.close, self.config.close):
            try:
                close()
            except Exception as error:
                failures.append(error)
        if failures:
            raise RuntimeError('One or more owned providers failed during shutdown; all remaining cleanup was attempted') from failures[0]
