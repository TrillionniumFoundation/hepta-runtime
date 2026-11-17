# HIA path and literal error formatter

Qualified source: 2464624eee505339adfd6b6297a7f7eb00672bd8, native/literal_error.hepta. Install the exact bytes as native/path_error.hepta when upgrading a caller's complete source closure. The generated module name remains literal_error. No JSON, integer or assembly reserialization is part of installation.

The entry accepts read-only input, mutable output and mutable workspace spans and returns an unsigned 32-bit result. The output is the exact UTF-8 diagnostic, with no NUL terminator or newline. Successful return is its byte length. Invalid framing or UTF-8 returns 0xffffffff; insufficient capacity returns 0xfffffffe. Complete output and workspace tails are covered by actual evidence.

The predecessor's HBRDS001, HMDSR001 and HOSER001 contracts, errno mapping, integer file-descriptor rendering, two-filename rendering and Unicode escaping remain qualified. All 32 predecessor function bodies are retained under exact inverse relocation; old entry f0 becomes f32. The two new functions are the dispatch entry and the literal extension.

Only HBRDS001 kind3 literals with errno0 admit the new classes: 15 is the exact type name Error used by binascii.Error, 16 is NotImplementedError, and 17 is RuntimeError. The 64-byte header stores magic at0, kind3 at8, caller sequence at16, class at24, errno0 at32, literal byte length at40, filename kind0 at48, and payload length at56. The two lengths must both equal input length minus64. The payload is valid UTF-8 and is emitted unchanged after the exact class name and ": ". Embedded NUL and other Unicode scalars are preserved. These new classes are not admitted through the metadata or two-filename envelopes.

The workspace requirement remains12,288 bytes. Its first10,152 bytes are the exact unchanged platform table, SHA-256 bound in native/platform_data.json; successful admission and output-capacity rejection may install this table. A short workspace or invalid input preserves all spans. The untouched workspace suffix and all output bytes beyond the returned message remain exact.

The compile profile is Linux x86-64, retained actual HIA B3 bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0. The flat image is312,298 bytes, SHA-256531c65b74394565a9c2a8ba70f9daa0d466f9c0cb2567525d4397593b6c80943. Original diagnostics use the frozen CPython3.12.3 executable and Unicode15.0.0/C message locale.

Actual qualification completes22,336 semantic HIA cases and1,255 private boundaries, reusing21,901 complete predecessor original results and executing435 new original literals. The latter cover every Unicode scalar for all three new classes, exact Base64/urandom messages, and lengths through one MiB plus one. Eight physical mutations and two complete relocations pass independent full read; the uploaded56,270-file archive is restored and read without replay.

A caller must rebind and qualify its complete compiled dependency graph before replacing an installed child image. This private formatter does not by itself qualify write/upload, new public routes, another platform or the complete runtime.
