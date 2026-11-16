# Current SDK task registry with queued responses

This isolated revision retains the 110 qualified current RMCP 3.9.0 request,
cancellation and drain conversations and adds eight normal response-queue
conversations. HIA owns the FIFO, request generations, cancellation selection,
sink claim, send acknowledgment and EOF drain decisions. A mechanical host
will later retain actual request/transport storage; this package does not
qualify that host, a real worker, or full asynchronous runtime behavior.

The original SDK source and exact d3d75 Cargo.lock remain unchanged. Rust
1.95.0 runs only in CI. Native and original conversations each keep their
60-second deadline, reference build commands keep 180 seconds, and the job
remains 15 minutes. The workflow first writes runtime paths through GITHUB_ENV.

`authoring/request_tasks_v1.txt` and `author_registry_v1.py` preserve the old
author inputs. `QUEUE_DELTA.json` identifies the 25 exact retained function
ASTs, nine changed state/row functions, and three queue helpers. No expected
wire is used to implement the owner. The newly authored Rust observation
steps merely release owned handler/send gates and observe the unchanged SDK.

The source manifest and Git IDs cover all files. The full recipe builds two
HIA images and a fresh exact-lock SDK reference, captures all 118 cases and
all mutable buffers, performs ten physical evidence changes, and requires a
strict read-only reader with eleven real refusal probes. The old source and
both prior failed runs remain frozen in the request-task-v1 handoff.

See `native/sdk_request_task_abi.md` for the 192-byte revision-2 ABI. The future
public graph reserves slot 58 for this owner, with 59 descriptor rows at 8192
and a 16384-byte engine; this recipe is still a two-component private domain.
