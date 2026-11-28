# Native HIA job owner candidate

This candidate preserves the complete canonical public repository and adds the privately qualified HIA controller/runtime work through controller protocol v25. The v25 long-lived job supervisor executes the pinned HIA image with sealed request/input and explicit file-descriptor authority. Startup requires the complete pinned controller inventory; incomplete releases do not silently fall back.

The implementation still contains Rust transport and Python SSH/bootstrap/status code, plus compatibility paths for prior controller protocols. This checkpoint does not claim full removal of that host stack or production activation.

## Source provenance

The public parent is 9d12416a0f6fec83cf25bd7c7bb511d718827650. The privately tested source derives from 80574d1d17d1327cbe034045ac46682a2cb70322 plus the included v25 patch. The source manifest records all 1,061 tracked private paths. Publication overlays those paths on the public parent and retains its 4,249 additional paths. The public tests/rea_mcp_external.rs is retained explicitly: the private copy had inadvertently dropped the existing /dev/full diagnostic regression, which has been restored and passed.

The code diff has 24 paths. No public docs, CI, license, script, archive or other extra path is removed. Evidence records source tree identities, the exact v25 patch and every runtime/owner/worker/controller artifact pin.

## Qualification boundary

The new dev runtime 083ba0ef, native job owner b94b97e5, worker entry 52254183 and controller v25 completed 39 application calls across all 11 HIA tools, 1,311 RPC records, a 256-case independent semantic comparison and four retained cold replays. The campaign uses the retained d366 Store (9adbefbc). Direct results were reused with their original provenance. All 39 jobs have valid native owner records, binary receipts and terminal witnesses; a live owner executable was independently observed as the pinned native HIA image.

The same dev binary returned the completed request in 451 ms with a sealed, full diagnostic sink under the unchanged 15-second limit, with one original job and a verified terminal witness. The exact controller-role unit test also passed.

The restored public external MCP stderr test passed separately. Cargo test generated a distinct test-profile runtime (fbc5e529), so its result is not mislabeled as an execution of the dev binary. The dev build was restored byte-for-byte and retained outside Cargo target.

These results establish compatibility of the new owner/entry/runtime pair with the retained Store. They do not replace qualification of the final freshly rebuilt integrated Store. A full all-target runtime test suite and non-Linux builds were not run. No default branch or live service is changed by this branch.
