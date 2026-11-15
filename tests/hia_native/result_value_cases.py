# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Typed SDK response cases; Rust owns projection and canonical Number text."""
import copy


def cases():
    values = []

    def add(variant, body, label):
        values.append({"variant": variant, "body": body, "label": label})

    text = ["", "plain", "\"\\\n\r\t\x00\x01\x08\x0c\x1f", "中😀é\u2028\u2029", "/<&>", "x" * 4096]
    for index, value in enumerate(text):
        for error in (False, True):
            add("text", {"text": value, "error": error}, f"constructor-text:{index}:{error}")
    add("complete_some_null", {}, "constructor-structured-some-null")
    add("error_some_null", {}, "constructor-error-data-some-null")
    meta = {
        "io.hepta.runtime/request-v8": {"caller": "preexisting", "nested": [None, False, {"x": -0.0}]},
        "io.hepta.runtime/retention-v8": {"state": "caller-owned"},
        "original_metadata": ["keep", {"k": "v"}], "a": 18446744073709551615, "z": [1e-300, 1e300],
    }
    annotations = {"audience": ["assistant", "user"], "priority": 0.1, "lastModified": "verbatim-not-date"}
    blocks = [
        {"type": "text", "text": text[2], "annotations": annotations, "_meta": meta},
        {"type": "image", "data": "AAEC/+/=", "mimeType": "image/png", "annotations": annotations, "_meta": meta},
        {"type": "audio", "data": "raw-base64-field", "mimeType": "audio/wav", "annotations": annotations, "_meta": meta},
        {"type": "resource", "resource": {"uri": "file:///path", "mimeType": "text/plain", "text": text[3], "_meta": meta}, "annotations": annotations, "_meta": meta},
        {"type": "resource", "resource": {"uri": "blob://path", "mimeType": "application/octet-stream", "blob": "AA==", "_meta": meta}, "annotations": annotations, "_meta": meta},
        {"type": "resource_link", "uri": "urn:原始", "name": "link", "title": "Title", "description": text[2], "mimeType": "text/plain", "size": 18446744073709551615,
         "icons": [{"src": "data:image/png;base64,AA==", "mimeType": "image/png", "sizes": ["16x16", "any"], "theme": "dark"}], "_meta": meta, "annotations": annotations},
    ]
    for index, block in enumerate(blocks + [None]):
        for result_type in (None, "complete"):
            for is_error in (None, False, True):
                body = {"content": [copy.deepcopy(block)] if block is not None else copy.deepcopy(blocks), "_meta": copy.deepcopy(meta),
                        "structuredContent": {"arbitrary": [True, None, text[2], -0.0, 18446744073709551615], "_meta": meta}}
                if result_type is not None: body["resultType"] = result_type
                if is_error is not None: body["isError"] = is_error
                add("complete", body, f"complete:{index}:{result_type}:{is_error}")
    for value in [None, False, 0, -0.0, "", [], {}, meta, {"io.hepta.runtime/request-v8": 1}]:
        for code in [-32700, -32602, -32603, -1, 0, 2147483647, -2147483648]:
            body = {"code": code, "message": text[2]}
            if value is not None: body["data"] = copy.deepcopy(value)
            add("error", body, f"error:{len(values)}")
    for index, state in enumerate(text):
        for value in [None, {}, meta]:
            body = {"resultType": "input_required", "requestState": state}
            if value is not None: body["_meta"] = copy.deepcopy(value)
            add("input_required", body, f"input-required:{index}:{len(values)}")
    for status in ["working", "input_required", "completed", "failed", "cancelled"]:
        for ttl in [None, 0, 18446744073709551615]:
            body = {"resultType": "task", "taskId": text[3], "status": status, "statusMessage": text[2],
                    "createdAt": "arbitrary-created", "lastUpdatedAt": "arbitrary-updated", "ttlMs": ttl,
                    "pollIntervalMs": 18446744073709551615, "_meta": copy.deepcopy(meta)}
            add("task", body, f"task:{status}:{ttl}")
    return values
