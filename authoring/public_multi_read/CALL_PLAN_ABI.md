# Public multi-file handler call plan

The pure HIA entry consumes a complete successful HMRPR001 result and actual
installed-config replies. The owning gateway binds continuations to the same
typed request and installed configuration; public arguments cannot choose phases
or provide replies.

The request is a 48-byte HMRLQ001 header:
phase at 8 (0 start, 1 host-mode reply, 2 path-root reply),
current path index at 16, typed extent at 24, prior root-record bytes at 32,
and feedback bytes at 40. Payload concatenates typed result, prior root records
and one HRCFGM01 reply. Prior records are u64 byte length followed by complete
root UTF-8, exactly one per path before the current index. Phases 0 and 1 require
index zero and no root records; phase 0 has no reply.

Phase 0 checks the original count, limits, each path's syntax and its duplicates
in order, then asks installed config operation 11 for the exact configured host.
A successful mode reply is HRCFGM01, status zero, diagnostic zero, payload
HRCFMOD1 plus u64 mode (0 isolated, 1 operator). Other modes are private-frame
errors. Phase 1 requires operator mode and requests operation 12 for path zero.
Operation 12 retains the original remote-path permission check and longest
allowed read root. Each successful phase-2 reply appends the root and advances
to the next path. After the final path the exact compact sorted original JSON
request is produced. No file is opened by this owner.

The output has a 64-byte HMRLR001 header:
status at 8 (1 original business/config error, 2 config request, 3 query JSON),
next phase at 16, next path index at 24, admitted file/response limits at 32/40,
payload length at 48 and retained root-record bytes at 56.
Payload begins at 64; updated root records follow the payload. Their tail is
nonempty only for an advancing phase-2 config request. Error replies preserve
the original diagnostic bytes. Paths, roots and their order are not normalized.

Return value is the complete extent. Output shorter than 64 returns 0xfffffffe;
invalid framing returns 0xffffffff without mutating output or workspace.
Workspace below 512 or insufficient output returns 0xffffffd0 and the unchanged
HGRWS002 32-byte growth request. Sizing precedes publication; output tail bytes
are unchanged. Native/public gateway qualification remains separately required.
