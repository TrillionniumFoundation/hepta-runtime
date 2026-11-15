# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact borrowed-buffer Builder class from the qualified legacy author."""
import ast
from tools.generate_hia_selfhost import Builder

class BorrowBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.FloorDiv, ast.Mod)):
            arguments = [self.cast(self.expr(value), 'u64') for value in (node.left, node.right)]
            return self.op('int.div.checked' if isinstance(node.op, ast.FloorDiv) else 'int.rem.checked', arguments, 'u64')
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_range':
            values = [self.expr(value) for value in node.args]
            if values[0] == values[1]:
                return self.op('buffer.move_within', [values[0], *(self.cast(v, 'usize') for v in values[2:])])
            source = values[1]
            if source[1] == 'mutbuf':
                source = self.op('borrow.read', [source], 'readbuf')
            result = self.op('buffer.copy_range', [values[0], source, *(self.cast(v, 'usize') for v in values[2:])])
            if values[1][1] == 'mutbuf':
                self.op('loan.end', [source])
            return result
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in self.signatures:
            arguments = [self.expr(value) for value in node.args]
            signature = self.signatures[node.func.id]
            loans, converted = [], []
            for value, kind in zip(arguments, signature[0], strict=True):
                if value[1] == 'mutbuf' and kind == 'readbuf':
                    value = self.op('borrow.read', [value], 'readbuf')
                    loans.append(value)
                converted.append(self.cast(value, kind) if value[1] != kind else value)
            result = self.op('call', converted, signature[1], function=self.names[node.func.id])
            for loan in loans:
                self.op('loan.end', [loan])
            return result
        return super().expr(node)
