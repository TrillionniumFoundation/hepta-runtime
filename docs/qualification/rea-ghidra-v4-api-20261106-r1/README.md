# Historical revision-4 Java API preflight

This is the retained, unpublished four-analyzer candidate. Its profile is `hepta.ghidra.12.1.4.elf-functions.v2` and its analysis bridge SHA-256 is `95f26c924c445fce23108ce718667ed72def831fed63a1e36589c7b1177edcc7`. These results are not transferred to the later default-analyzer profile.

Eight actual Java API calls completed on the fixed owned ELF: functions; function, xrefs and decompile at entry `0x401106` and interior `0x401107`; and the expected unmapped-address error at `0x0`. The retained receipt reports seven successful operations and one expected failure, 12 internal plus one external function, stable input/installation/JRE/bridge identity, matching entry/interior observations and a 70.9376-second total run. The compile completed separately in 3.1938 seconds.

The archive is the original exported byte sequence, SHA-256 `ab73a304a46b33ae8a44665c0da5b2994c6b2a56ac288ef5f1af7898ec8754d6`, 57,860 bytes. Its 46 files contain 800,144 uncompressed bytes. `evidence-manifest.json` independently enumerates every member and digest. The archive retains raw stdout/stderr, launch/terminal observations, bridge/collector snapshots, the owned input and receipts.

This preflight used the historical Ghidra-only installation boundary (3,002 files). It does not attest the GPL subtree, the later default profile, a Rust MCP binary, original complete Evidence parity, cancellation/restart equivalence or deployment on another platform. The native report remains partial.

Fixed common identities: Ghidra 12.1.4 release ZIP `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`; Java launcher `1bf1aaef01e4f8d7c85d913c60fb2ee4624cbe54d4053254c59657b7ea913b25`; input `ec301f409d22314b43b4392fa80ada28213cd75ca77c6cbbbbfe1454555dd64a`.

See the separately identified [default-profile diagnostics](../rea-ghidra-v4-default-20261106-r1/README.md).
