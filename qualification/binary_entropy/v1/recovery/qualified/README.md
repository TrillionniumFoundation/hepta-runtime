# Actual process-lifetime HIA entropy and UUID4

This frozen qualification executes 42 input groups and 97 applications per role against the unchanged CPython urandom/uuid4 entries and one immutable HIA native image. Every application process has a 60-second bound. The source check, complete build archive, all inputs, complete native observation format, pure readers, seven physical mutations and two relocations are frozen before execution.

Random values from separate kernel calls are not expected to be equal. Each native raw/UUID result is compared to its own complete actual syscall bytes and independently retained state. The original UUID result is checked against its delegated real urandom output. Both roles must agree on exact errors and every persistent, forgotten or reused descriptor. Observer-off cases retain complete external state without an internal callback.

The admitted build is a74ab0d0a4158c72f85921119dad76aca89d6a23 (CI 44148710357), with a 114688-byte ELF whose SHA256 is bd54d90278b44be6a592590c57d575f41821ce0dfbb605a5d668fb3e5c604950. Its complete uploaded archive and all seven original build guards are reread before applications. No compiler or native image is invoked by any evidence reader.

This is a private, serialized Linux x86-64 process-lifetime capability. It is not yet wired to write/upload or a public runtime route. The original stack must remain until the complete final public graph is qualified. Arbitrary Python signal handlers, allocation failure, forked-cache inheritance and concurrent CPython cache installation are outside this serialized profile. Private malformed/transport qualification and uploaded independent admission remain separate required gates.
