#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Adapt the existing one-shot native transport to the exact HIA write parent."""
from pathlib import Path
import argparse
import hashlib
import json


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    original = (root / "asm/binary_read_stdio.S").read_text()
    # The production helper has no observer descriptors or fixture selectors.
    lines, enabled, stack = [], True, []
    for line in original.splitlines(keepends=True):
        if line.strip() == ".if HBRH_OBSERVE":
            stack.append(enabled)
            enabled = False
        elif line.strip() == ".else":
            assert stack
            enabled = stack[-1] and not enabled
        elif line.strip() == ".endif":
            enabled = stack.pop()
        elif enabled:
            lines.append(line)
    assert not stack
    production = "".join(lines)
    replacements = [
        ("One-shot byte transport for the fixed HIA binary-read operation.",
         "One-shot byte transport for the fixed HIA binary-write parent operation."),
        (" * and process lifetime. HBRH_OBSERVE is a fixed build-time fixture constant;\n * the production image has no journal entry or descriptor selection path.",
         " * and process lifetime. No observer or request-selected capability is installed."),
        ("0x3130305144524248 /* HBRDQ001 */", "0x3130305157504248 /* HBPWQ001 */"),
        ("0x3130305344524248 /* HBRDS001 */", "0x3130305257504248 /* HBPWR001 */"),
        ("    xor edi, edi\n    xor esi, esi\n    call binary_read_body_create",
         "    call hia_process_orphans_create\n"
         "    cmp rax, -4095\n    jae .Lbrh_fatal\n    mov [r15+192], rax\n"
         "    xor edi, edi\n    xor esi, esi\n    mov rdx, rax\n"
         "    call binary_entropy_create\n"
         "    cmp rax, -4095\n    jae .Lbrh_fatal\n    mov [r15+200], rax\n"
         "    xor edi, edi\n    xor esi, esi\n"
         "    mov rdx, [r15+192]\n    mov rcx, [r15+200]\n"
         "    call binary_parent_owner_create"),
        ("    call binary_read_body_invoke", "    call binary_parent_owner_invoke"),
        ("    call binary_read_body_release", "    call binary_parent_owner_release"),
        ("    call binary_read_body_destroy", "    call binary_parent_owner_destroy"),
        ("    cmp qword ptr [r13+8], 3\n    jne .Lbrh_fatal",
         "    cmp qword ptr [r13+8], 3\n    jne .Lbrh_fatal\n"
         "    cmp r14, 128\n    jb .Lbrh_fatal"),
        ("    mov rdi, r13\n    mov rsi, r14\n    mov rdx, [r15+32]",
         "    lea rdi, [r13+64]\n    lea rsi, [r14-64]\n    mov rdx, [r15+32]"),
        ("binary_read_helper_error_call_displacement", "public_binary_write_error_call_displacement"),
        (".Lbrh", ".Lbwh"),
    ]
    current = production
    edits = []
    for old, new in replacements:
        count = current.count(old)
        assert count > 0, old
        if old not in (".Lbrh", "binary_read_helper_error_call_displacement"):
            assert count == 1, (old, count)
        current = current.replace(old, new)
        edits.append({"old": old, "new": new, "count": count})
    inverse = current
    for row in reversed(edits):
        assert inverse.count(row["new"]) == row["count"]
        inverse = inverse.replace(row["new"], row["old"])
    assert inverse == production
    assert "journal" not in current and "HBRH_OBSERVE" not in current
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    (output / "public_binary_write_stdio.S").write_text(current)
    report = {"schema": "hepta.runtime.public-binary-write.stdio-author.v1",
              "original_read_transport": pin(original.encode()),
              "original_production_projection": pin(production.encode()),
              "source": pin(current.encode()), "edits": edits,
              "complete_mechanical_inverse": True,
              "application_decisions_in_hia": True,
              "original_parent_and_body_sources_unchanged": True,
              "parent_death_signal_and_race_check_retained": True,
              "process_orphan_pool_and_entropy_retire_at_process_exit": True,
              "public_binary_write_registered": False}
    (output / "STDIO_AUTHOR.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report["source"], sort_keys=True))


if __name__ == "__main__":
    main()
