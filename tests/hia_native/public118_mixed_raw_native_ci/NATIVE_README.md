# Native-only 108 retained public stdio comparison

The exact public ELF is 24854528 bytes with SHA-256 7968583b5493cf983a19d24b6476e3864c0253dfbce87d785246b6dbfa8376b8. It is copied and reverified from the complete independent-qualified 436-source public118 build. This gate uses the same full-stream collector, input generator, filesystem observer and strict differential reader as its complete retained original captures. It records every actual stdout line, stderr byte, partial input, barrier, EOF, exit and fixture state without assuming a response count.

The six original domains are unchanged from source 24b9cba8d550bcab1e3242479442d06f39046a62 / run 44013495462. The earlier native source 3b4746cc8df619898757dc49ff51da015bc9b398 / run 44014616058 remains five PASS domains and the real legacy params:null mismatch, with every byte independently read in run 44015612075.

Only the new native public processes execute. Original semantics and the native build are not replayed. The full original capture and its four physical controls are reopened, followed by four fresh native differential controls. All input, source, wire, filesystem, process and proof bytes remain in the final archive. The exchange, full lane and job budgets remain 60 seconds, 180 seconds and 15 minutes. This gate does not qualify concurrent public WAIT, cancellation, full async or whole-runtime replacement.
