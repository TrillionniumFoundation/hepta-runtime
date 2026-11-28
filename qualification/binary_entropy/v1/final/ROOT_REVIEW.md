# Final private entropy and UUID4 review

## Decision and production rows

The process-lifetime entropy primitive is qualified for the frozen serialized Linux x86_64 / CPython 3.12.3 profile. The production body is the unchanged 23-function HIA source at a74ab0d0a4158c72f85921119dad76aca89d6a23, with one native capability custodian and the shared append-only process orphan primitive. INSTALL_ROWS.json lists the four unique production rows and the two already shared HIA build components. SOURCE_ROWS.json supplies each complete rebuild and qualification source set.

There is no Python, Rust or libc runtime requirement in the primitive. Python appears only in source authoring, original reference capture, private image carriers and evidence readers. The standalone fixture is not a production entry point.

## Behavior established by retained actual applications

The frozen application domain completed 97 original and 97 native calls in 42 process cases: 44 successes and 53 errors, including seven observer-disabled pairs. All 325 HIA control transitions and 228 actual capability calls are accounted for. The full native journal contains 2,727 events and 18,785,520 bytes. Five forgotten descriptors were transferred to the process-wide pool.

The checks cover sticky getrandom EPERM/ENOSYS fallback, partial and interrupted operations, exact device-open exception classes, one-attempt initial/cache fstat behavior, preserved initial fstat errors across candidate close, cache read errors/EOF, actual closed/replaced cached descriptors, FD0 and descriptor pressure. Random values are compared only against the same application's captured real syscall payload. Independently generated random values are not required to equal one another. UUID4 version, variant and lowercase encoding are checked against each call's own raw16 bytes.

The first producer finished all applications and then failed its pure reader at the deliberately closed cache descriptor. The unchanged capture was recovered by the exact reader correction in 2d32972bc9e72ea3421ce35003e15df0b27e94dc. Seven honestly resealed physical refusals and two complete relocations passed. The independent uploaded-archive reader 7d1106f521dfbd4a3b884030d97cd30f6a6cb7ff reread all 10,748 recovered logical files, checked 14,169 unchanged filesystem entries and exercised eleven new capability guards. No original/native application was replayed.

## Private transport and final independent read

The separate private domain at20803939424006be4ca7b9d1793101662202bd6b completed 216 fixed raw HIA entry calls and 24 rejected native packets. These are explicitly synthetic protocol inputs, not additional claims of kernel randomness. The 37 framing checks and 29 flow programs cover capacity, exact duplicate-resume retry, interrupted/partial/zero progress, sticky fallback after partial data, high-bit device/inode values, descriptor0, all sixteen EOF remainder messages and ignored candidate-close failures.

The pure model checked all 1,397 retained capture files and 3,075,320 complete buffer bytes: input, output, workspace, unused tails, canaries, native context, all four native arenas and the shared pool. All rejected native packets left complete ownership state unchanged. Four physical mutations with updated hashes were refused and two complete source/capture relocations passed.

The first uploaded reader failed a tuple-versus-JSON-array comparison after fully checking the private buffers. That failure is retained and reproduced. The corrected reader normalizes the complete pure result through the existing canonical JSON serializer at three comparison boundaries; it does not drop fields, relax byte checks or change a HIA instruction. The final reader e32b1e0a70da23704958ea4796055b9d09223212 passed, reading all 13,975 uploaded logical files, checking16,510 unchanged entries, exercising eleven new capability guards and rereading14,391 saved guard file references. It executed no HIA or original application.

## Required integration lifetime

One serialized entropy context belongs to the entire process. Create it with the same append-only pool already shared by the other file primitives. Release completed result loans without resetting availability or closing the cached entropy descriptor. Retain the context and its cache until process exit. There is deliberately no destroy or reset API.

On invalid cached-descriptor identity, forgetting a numeric descriptor never closes it. Later descriptor-number reuse is compatible with append-only historical pool records. The pool must never be treated as a list of descriptors to close.

Strict Base64 and entropy introduce wire literal classes15 Error,16 NotImplementedError and17 RuntimeError. The existing path_error32 formatter does not accept these classes. Its HIA literal-error successor must be independently qualified before the writer/upload graph uses those errors.

## Limits and repository status

Each actual or private application process retains its60-second limit; pure readers retain180seconds, builds900seconds and workflows15minutes. FAIL and UNKNOWN remain distinct and no unknown/completed application is automatically replayed. Expanded evidence is retained; no unverified copy was deleted.

Arbitrary Python signal handlers, allocator failure behavior, concurrent CPython cache installation and fork-inherited Python cache behavior are outside this serialized profile. Public route, binary write/upload, full SDK integration, all136handlers and old-stack removal are not claimed. The integration branch remains at5a5a35b355b7b58a23da797acd0002a832fc919b. This final package is ready for the downstream HIA writer graph; it is not a declaration that the whole runtime migration is complete.
