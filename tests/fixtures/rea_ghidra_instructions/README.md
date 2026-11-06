# Ghidra instruction-window contract fixture

`contract-window.json` is a synthetic trust-boundary fixture. It models a complete, three-instruction Listing over two disjoint inclusive function-body ranges. The bytes and source identity are constructed data, not output from Ghidra and not evidence that an engine ran.

Its original REA 6.8.0 value projection is `instruction_window`. The surrounding native observation adds an admitted source identity, exact byte rows, row/text budgets, and a digest of UTF-8 instruction text joined with a single newline and no final newline. Tests corrupt those independent facts to check rejection.

Actual engine output, cancellation, error handling, process identity and cleanup require a separate fixed-candidate real-engine run.

`owned-instructions.S` is an uncompiled x86-64 source fixture for a future real-engine gate. It supplies a 9-byte leaf (`b81100000083c007c3`, three instructions) and a separate 4,097-instruction function (4,096 one-byte NOPs plus RET) that must not become a successful truncated window. Actual FunctionManager bodies, counts and rejection reasons still require engine observation; source declarations alone are not qualification.

A bounded preparation command is `gcc -nostdlib -no-pie -Wl,--build-id=none -Wl,-e,_start -o OWNED_OUTPUT owned-instructions.S`, with an explicitly pinned compiler and a new private output directory. Independent `nm` and `objdump` outputs must be retained. Do not execute the produced ELF.
