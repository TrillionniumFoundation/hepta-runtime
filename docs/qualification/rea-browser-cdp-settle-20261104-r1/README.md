# CDP phase-drain review and isolated regression receipt

This receipt covers the reviewed CDP patch and three socket-pair regression tests. It does not qualify the complete HeptaRuntime binary, child cancellation or a real Chrome session. The extracted module uses a cancellation stub returning success; the existing runtime lifecycle harness remains the required gate.

The patch closes two event-ordering gaps: a resolved page promise did not guarantee that Network loading terminals had been consumed before HAR rows were cloned, and a late Fetch gate error could otherwise arrive during Browser.close's tolerated pipe-close failure. Each phase now drains the exact URL occurrence multiset, including repeated resources, the entry page and the denied probe, until all requests are terminal and every gate acknowledgement has been checked. It uses the original absolute capture deadline. HAR and the transition to Browser.close require that settled state.

The same patch corrects missing-body semantics found by the independent Python/native comparison: missing bodies omit text and size; an observed empty body retains text="" and size=0. The socket fixture asserts both cases.

The tests execute the actual patched Cdp module with its normal JSON, hashing and UnixStream transport. The peer deliberately sends Runtime.evaluate's response before late network completion and a pending gate acknowledgement. A separate case sends a late gate error; another omits the second occurrence of a repeated URL. All three pass under the recorded locked minimal crate. The receipt preserves exact source/patch hashes and command output.

Root separately addressed the directory-path identity finding with descriptor-versus-path checks and ancestor/output rename tests. The full runtime has subsequently changed from this extracted test snapshot; the receipt records the observed integration relationship without treating this unit test as a qualification of that binary. Original logs remain in the private development cache. No upstream REA operation is marked equivalent by this review.
