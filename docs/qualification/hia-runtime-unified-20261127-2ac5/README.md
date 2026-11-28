# Unified Runtime reader qualification

The ordinary merge `8e721fd945b28c3cd48a25be3a77103b51668989` retains both
`d3a19a161f2c6cd7177bee530152e7179344fbe4` and
`a7b9aadf8639c2d7187672ca85c64abd57608eab`, including every original common
admission repair and its historical failure/CI receipts. The merge has no
conflicts and its tree is `28d7a00a35618dcdfc3fbc143090cc40577f3521`.

The six original reader control commands passed on that merged source:
18 installed-public, 39 common source/import admission, 9 language coverage,
10 bootstrap distribution, 7 execution trace readback, and 6 execution-chain
controls. The archive retains complete stdout/stderr and command results;
every archive member was read back and matched against its original bytes.
The accompanying CI change runs these same controls on the unified branch.

These 89 controls do not qualify an actual native cold build, Store package,
installation, or public START/STATUS campaign. Those execution gates remain
OPEN. The original common workflow source/distribution pins and all of its
execution obligations are retained; they must be explicitly updated to the
final matching source and distribution before qualifying that final tuple.
