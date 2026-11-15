# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Retain the exact native ABI in demand-zero anonymous test allocations.

The fixed native ELF adapters use anonymous mappings for the same reason: a
declared 256 MiB arena need not fault every unused page before the first call.
Invocation, source custody and the two exact canary spans remain owned by the
existing qualified NativeSession implementation.
"""
import ctypes
import mmap
import threading

from hia_native_loader import NativeSession


class MappedSession(NativeSession):
    def __init__(self, module, *, output_capacity=None, workspace_capacity=None):
        self.module = module
        self.output_capacity = module.metadata["output_capacity"] if output_capacity is None else output_capacity
        self.workspace_capacity = module.metadata["workspace_capacity"] if workspace_capacity is None else workspace_capacity
        for value, maximum in ((self.output_capacity, module.metadata["output_capacity"]),
                (self.workspace_capacity, module.metadata["workspace_capacity"])):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError("invalid native invocation capacity")
        self._lock = threading.RLock()
        self._output = self._workspace = None
        self._output_mapping = self._workspace_mapping = None
        try:
            self._output_mapping = mmap.mmap(-1, self.output_capacity + 16,
                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            self._workspace_mapping = mmap.mmap(-1, self.workspace_capacity + 16,
                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            self._output = (ctypes.c_char * (self.output_capacity + 16)).from_buffer(self._output_mapping)
            self._workspace = (ctypes.c_char * (self.workspace_capacity + 16)).from_buffer(self._workspace_mapping)
        except BaseException:
            self.close()
            raise

    def close(self):
        with self._lock:
            # Drop every exported ctypes view before unmapping its allocation.
            self._output = self._workspace = None
            for name in ("_output_mapping", "_workspace_mapping"):
                mapping = getattr(self, name)
                if mapping is not None:
                    mapping.close()
                    setattr(self, name, None)
