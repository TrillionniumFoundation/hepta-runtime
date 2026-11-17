# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Names only; this stage defines its inputs in DOMAIN.json."""
def schemas():
    return [dict(name=n) for n in ("file_info","binary_read","binary_write","binary_upload","binary_patch_inode")]
