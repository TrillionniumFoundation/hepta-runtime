# Composed Authority, Batch and Bellman frontend

This package composes the unchanged Authority91 frontend with the frozen dynamic
Batch author and the frozen Bellman pending author. The canonical order is
Authority91, Batch, then Bellman. Both authors verify exact retained function
graphs and reversible changes. The source recipe keeps the existing catalog and
does not establish a new public tool qualification.

Batch retains child 13 -> global slot 47 and phases 6/106. Authority retains child
12 -> slot 56 and its previous phases. Bellman uses child 14 -> slot 57, phases
15/16/17 and 115/116/117, and the phase-97 host-return boundary. Its private state
at 1280 and trusted host control at 1344 remain unchanged. The SDK request
registry belongs at global slot 58 in the separately authored host graph.

The unchanged Bellman private ABI corpus is included to check that adding Batch
source wrappers preserves pending/poll/cancel/retire behavior in the actual new
HIA image. Its child acknowledgments are test-owned records. These controls do
not execute a worker, an SDK, Rust, or public transport. They cannot qualify a
complete public graph, advertise new catalog entries, or permit legacy removal.

Local compilation requires an independently verified copied B3 compiler cache.
Source and corpus must be frozen in Git before the first native execution.
Use `compose.py --check` with a fresh work directory to reproduce the complete
HIA and composition files using the pinned Hepta source authoring library.

The Batch v4 full native lane timed out at its existing 180-second limit. That
failure is retained and must be resolved independently. Source composition
does not change any Batch case, deadline, parameter rule, or implementation.
