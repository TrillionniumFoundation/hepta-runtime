# Actual private publication-worker lifecycle

This candidate uses the exact four-image native executable built at d4987615
and independently reread at 9a5e13bd. It does not rebuild or execute Rust, and
does not modify the unique shared production graph at 320862f0.

The input-only domain has 24 independent processes: all 8 retained original
direct-future scenarios plus borrow, closed-queue, 33-job FIFO/growth and invalid
lifecycle controls, each with the observer enabled and disabled. Every process
retains its complete stdin, stdout, stderr, journal, input/output buffers and
filesystem snapshots. Directory locks are real owned flock calls; blocking is
observed through actual child syscall/descriptor state. The native queued
fixture consumes its one slot with an additional real publication held in an
explicit blocker directory; the original used a real Condvar blocking task.
That physical difference is recorded, and only the exact intended task
lifecycle and final file-byte projection is compared to the existing original
evidence. Cache behavior and public SDK wire are not synthesized.

All journal calls contain the entire input64, output320, allocated HIA state
and actual return. Real clone/ACK/BEGIN/body/COMPLETE/wait4/borrow/release events
must form a complete ownership chain. Complete terminal body bytes must equal
the delivered borrow. Dropped queued or running bodies continue; borrowed
storage remains intact while another job completes. Four physically changed
and re-signed copies plus two complete relocations exercise the pure reader.

Limits remain 60 seconds per exchange, 180 per process/read, 15 minutes per CI
job. There is no outer subprocess timeout that pretends to reap nested setsid
children. Failure archives retain all completed bytes and partial streams.

A successful result qualifies this private executor boundary. It does not
qualify public SDK cancellation, current RequestContext, cache forget,
session isolation, the integrated publisher frontend or every Tokio shutdown
race. Those remain explicit subsequent shared-graph obligations.
