#!/bin/sh
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Opt-in X230/glibc execution profile. See allocator-policy.json.
# Usage: hepta-runtime-x230-glibc.sh /absolute/hepta-runtime [runtime arguments...]
# No stdout banner: stdout belongs to the runtime protocol.
set -eu

if [ "$#" -eq 0 ]; then
    printf '%s\n' 'usage: hepta-runtime-x230-glibc.sh /absolute/hepta-runtime [arguments...]' >&2
    exit 64
fi
case "$1" in
    /*) ;;
    *)
        printf '%s\n' 'x230 glibc profile: executable path must be absolute' >&2
        exit 64
        ;;
esac
if [ ! -f "$1" ] || [ ! -x "$1" ]; then
    printf '%s\n' 'x230 glibc profile: executable is missing or not executable' >&2
    exit 66
fi
case "$(/usr/bin/uname -s 2>/dev/null)" in
    Linux) ;;
    *)
        printf '%s\n' 'x230 glibc profile: Linux is required' >&2
        exit 78
        ;;
esac
case "$(/usr/bin/getconf GNU_LIBC_VERSION 2>/dev/null)" in
    "glibc "*) ;;
    *)
        printf '%s\n' 'x230 glibc profile: GNU libc is required' >&2
        exit 78
        ;;
esac

# Even an empty explicit value is caller-owned. Preserve tunables verbatim.
if [ "${MALLOC_ARENA_MAX+x}" != x ]; then
    case ":${GLIBC_TUNABLES-}:" in
        *:glibc.malloc.arena_max=*:*) ;;
        *)
            MALLOC_ARENA_MAX=1
            export MALLOC_ARENA_MAX
            ;;
    esac
fi
exec "$@"
