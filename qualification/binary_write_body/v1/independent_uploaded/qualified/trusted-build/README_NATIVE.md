# Binary write native build

The frozen source package compiles nine HIA runtime images with the copied,
already qualified B3 compiler, then uses the actual HIA ELF linker and image
packer. A private syscall-only carrier provides complete byte journals and real
kernel fault mechanisms for later reference qualification. The build never
executes that carrier or an original write application.

The generated write source is re-authored exactly. Every retained dependency is
verified by full bytes, and both native edits have exact forward/inverse proofs.
Build reading checks every compiler input/output and final ELF byte; four actual
corrupt copies must be refused, and two full relocations must pass. Those physical
copies remain in the evidence archive. No previous application is replayed.

The new controller preserves lock initialization, expected-before-decode,
process-global UUID state, full temp writes, publication, fingerprint and original
finally precedence. ABI.md and NATIVE_ABI.md define the caller and fixed graph.
Actual filesystem comparison, complete uploaded evidence recovery and downstream
public/Remote integration are required before claiming runtime replacement.
