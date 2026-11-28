# Private shared SSH owner embedding

The original `ssh_direct_abi.md` defines the five-policy generic owner and its
fixed command/result frames. This extension adds a trusted embedder factory;
public JSON cannot construct owners or supply pointers.

| Export | Inputs | Result |
| --- | --- | --- |
| ssh_direct_owner_create | observer, opaque | private owner address or negative errno |
| ssh_direct_owner_freeze | exact owner | closes admission in the actual shared policy |
| ssh_direct_owner_shutdown | exact owner | starts or observes the single persistent join |
| ssh_direct_join_result | exact owner | 1 pending, 0 success, negative persistent failure |
| ssh_direct_owner_gate_lock/unlock | exact owner | holds the original queue/commit boundary |
| ssh_direct_owner_state_lock/unlock | exact owner | borrows actual shared-policy workspace |
| ssh_direct_request_phase | retained request | actual admission phase |

A runtime selects one owner and shares it across sessions. Independent owners are
used only where the retained original test explicitly creates an independent
Proxy. A state/gate borrow forbids reentrant submit/freeze/shutdown; all references
must survive the borrow. Original submit/cancel/result/release interfaces and
one-shot Entry/guard custody remain unchanged.

This revision has no private-owner destruction API. The process owns its context
until exit; failed or uncertain joins keep their original custody and cannot be
converted to successful disposal. Default teardown integration must add an
explicit proven disposal boundary rather than free an owner while references,
reader work, join workers or quarantined children survive.

The production seven assembly files are byte-identical to the retained sources.
The qualification directory has seven explicit, reversible mechanical hook
relations, including incrementing the queue reference when the test's cancellation
observer already retains the request. These hook relations are not installed
production code. All five HIA images are unchanged.
