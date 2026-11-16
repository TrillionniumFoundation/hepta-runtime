# Local extract_lines implementation checkpoint

This independent candidate starts from installed102 commit
`0a8f9d6603abaf85f702ff2626dbe75f5d5f841c`. It does not replace the integration
branch or add a public catalog entry at this checkpoint.

`reference/TARGET.json` binds twelve complete production files to target
`d3d75c30719db966b004756f610007a7c723729e`, including the full original Cargo
lock. Eight exact excerpts include the typed parameter struct, actual public
method, complete body, optional endpoint parser, path helper, confirmation
renderer, and shift note. Each excerpt has exact source offsets and full-byte
SHA256/Git-blob identity. The body has 8,300 unchanged bytes.

The implementation must preserve this order:

1. Typed Parameters; effect admission; session workdir; source read policy and
   target write policy; request context.
2. Body parameter validation; source existence/read; strict source endpoints;
   source-position confirmation echo capped at thirty displayed lines.
3. Target parent creation; canonical shared lock; target existence/read and
   append endpoint; original EditableContent insertion.
4. A fresh target history snapshot; original atomic write; request ViewCache
   note_write; exact result and line-shift note; scope hints and permit release.

The original Local leaves for reads, mkdir, canonical keys, shared locks,
editable content, history, atomic writes, cache, and line validation will be
composed as HIA owners. Native adapters may carry buffers and execute the
fixed owner-selected effects; they will not implement edit policy in Python,
Rust, or assembly. Python remains build/capture/evidence tooling, and unchanged
Rust is an independent qualification oracle.

At this source checkpoint, no new HIA implementation has executed, no fresh
Rust comparison has run, and no public handler qualification is claimed.
Remote/SFTP and full Tokio cancellation are still separate open boundaries.
The existing 102 images do not mean that all 136 target handlers are ported.
