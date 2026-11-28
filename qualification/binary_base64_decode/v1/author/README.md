# HIA strict Base64 decoding for binary writes and uploads

This source-only author copies the exact already-qualified load/put/UTF-8 IR from the original read body and authors the CPython strict ASCII base64 state machine in HIA. It generates HIA assembly and a full composition receipt; it performs zero application, native compiler or Rust execution. Production build and actual reference comparison follow separately. The original binary operation source and exact CPython 3.12.3 wrapper/C implementation are frozen as references.
