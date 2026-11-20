# Copyright 2001-2024 Python Software Foundation. All rights reserved.
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Python-2.0
"""Strict Base64 DATA reference for the captured CPython 3.12.3 domain.

Derived from CPython v3.12.3 Modules/binascii.c, binascii_a2b_base64_impl,
and Lib/base64.py's ASCII string conversion. See COPYING.cpython-3.12.3.
This small reference is independent of the HIA implementation and does not
execute a retained binary or consult the host's changing decoder semantics.
Only the string input form used by this frozen qualification is admitted.
"""
import binascii

ALPHABET = {value: index for index, value in
            enumerate(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}


def strict_decode(value):
    if not isinstance(value, str):
        raise TypeError("frozen Base64 reference requires a string")
    try:
        data = value.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("string argument should contain only ASCII characters") from None
    if data.startswith(b"="):
        raise binascii.Error("Leading padding not allowed")
    output = bytearray()
    position = 0
    previous = 0
    padding = 0
    padding_started = False
    for index, symbol in enumerate(data):
        if symbol == ord("="):
            padding_started = True
            if position >= 2:
                padding += 1
                if position + padding >= 4:
                    if index + 1 < len(data):
                        raise binascii.Error("Excess data after padding")
                    return bytes(output)
            continue
        if symbol not in ALPHABET:
            raise binascii.Error("Only base64 data is allowed")
        if padding_started:
            raise binascii.Error("Discontinuous padding not allowed")
        padding = 0
        current = ALPHABET[symbol]
        if position == 0:
            previous = current
        elif position == 1:
            output.append((previous << 2) | (current >> 4))
            previous = current & 15
        elif position == 2:
            output.append((previous << 4) | (current >> 2))
            previous = current & 3
        else:
            output.append((previous << 6) | current)
            previous = 0
        position = (position + 1) % 4
    if position == 1:
        raise binascii.Error(
            "Invalid base64-encoded string: number of data characters ("
            + str(len(output) // 3 * 4 + 1)
            + ") cannot be 1 more than a multiple of 4")
    if position != 0:
        raise binascii.Error("Incorrect padding")
    return bytes(output)
