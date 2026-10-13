#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Transport-independent, explicitly pinned native MCP tool contract.
No execution, authentication bypass or user policy lives here. Private adapters and
future gateways consume the same definitions instead of implementing a second API.
"""
import hashlib
import json
import os
import pathlib
import re
import stat

ANNOTATIONS=('readOnlyHint','destructiveHint','idempotentHint','openWorldHint')
MAX_CONTRACT_BYTES=2*1024*1024


def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def catalog(tools):
    if not isinstance(tools,list) or not 1<=len(tools)<=512:raise ValueError('bounded nonempty tool catalog required')
    names=set();result=[]
    for tool in tools:
        if not isinstance(tool,dict):raise ValueError('invalid tool definition')
        name=tool.get('name')
        if not isinstance(name,str) or not re.fullmatch('[A-Za-z0-9_.-]{1,128}',name) or name in names:raise ValueError('invalid or duplicate tool name')
        if not isinstance(tool.get('inputSchema'),dict) or tool['inputSchema'].get('type')!='object':raise ValueError('object input schema required')
        if not isinstance(tool.get('description'),str) or not tool['description'].strip():raise ValueError('tool description required')
        hints=tool.get('annotations')
        if not isinstance(hints,dict) or any(type(hints.get(key)) is not bool for key in ANNOTATIONS):raise ValueError('all operation annotations must be explicit booleans')
        if hints['readOnlyHint'] and hints['destructiveHint']:raise ValueError('contradictory operation annotations')
        names.add(name);result.append(tool)
    return sorted(result,key=lambda tool:tool['name'])


def make_contract(tools):
    tools=catalog(tools)
    return {'schema':'hepta-native-tool-contract-v1','name':'Hepta Runtime Full Operator',
            'tool_count':len(tools),'catalog_sha256':hashlib.sha256(canonical(tools)).hexdigest(),
            'execution_backend':'existing hepta-runtime; no gateway execution implementation',
            'tools':tools}


class ToolContract:
    def __init__(self,value):
        if not isinstance(value,dict) or value.get('schema')!='hepta-native-tool-contract-v1':raise ValueError('unsupported contract version')
        self.tools=catalog(value.get('tools'))
        self.catalog_sha256=hashlib.sha256(canonical(self.tools)).hexdigest()
        if value.get('catalog_sha256')!=self.catalog_sha256 or value.get('tool_count')!=len(self.tools):raise ValueError('contract count or integrity mismatch')
        self.by_name={t['name']:t for t in self.tools}
    @classmethod
    def load(cls,path,expected_sha256):
        if not re.fullmatch('[0-9a-f]{64}',expected_sha256):raise ValueError('explicit contract-file SHA256 required')
        fd=os.open(pathlib.Path(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:raise PermissionError('trusted-owner non-writable-by-others contract required')
            raw=stream.read(MAX_CONTRACT_BYTES+1)
        if len(raw)>MAX_CONTRACT_BYTES or hashlib.sha256(raw).hexdigest()!=expected_sha256:raise ValueError('contract file digest mismatch')
        return cls(json.loads(raw))
    def verify_integrity(self):
        """Ensure live objects still match the originally reviewed definition.

        Python dicts are mutable even when loaded from a SHA-pinned file. Check
        both the source list and the independently mutable name index, or a
        later annotation change could silently turn a write into a read.
        """
        current=catalog(self.tools)
        if (hashlib.sha256(canonical(current)).hexdigest()!=self.catalog_sha256
            or len(self.by_name)!=len(current)
            or any(self.by_name.get(tool['name'])!=tool for tool in current)):
            raise ValueError('in-memory tool contract drift; review and pin a new version')
    def verify(self,tools):
        self.verify_integrity()
        actual=catalog(tools)
        if hashlib.sha256(canonical(actual)).hexdigest()!=self.catalog_sha256:raise ValueError('upstream tool contract drift; review and pin a new version')
    def allows(self,name):return isinstance(name,str) and name in self.by_name
    def read_only(self,name):return self.by_name[name]['annotations']['readOnlyHint']
