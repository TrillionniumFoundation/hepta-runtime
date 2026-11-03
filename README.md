# Hepta Runtime

Policy-enforced, multi-host MCP runtime based on Octofs, with durable process
ownership and optional REA artifact inspection.

## Weight-space research workbench

The optional `hepta-weight` domain runs a resident CPU model under the existing
process owner. It supports internal probes, temporary causal interventions,
bounded numerical analysis and exact typed weight patches. Candidate artifacts
retain base/backend identity, realized dtype changes and costs.

- [Enable profiles and use the six MCP tools](docs/weight-runtime/RUST_OWNER.md)
- [Compose probes, SVD and writer-column edits](docs/weight-runtime/ANALYSIS.md)
- [Python worker protocol and model adapters](workers/weight/PROTOCOL.md)
- [Implementation qualification and closed defects](docs/weight-runtime/QUALIFICATION.md)
- [Separate frozen paired evaluation](experiments/weight/evaluation/README.md)
- [Public MIT Qwen reconstruction and measured mechanism replay](experiments/weight/mit_replay/README.md)

Profiles default to disabled. The research worker does not train, replace an
active checkpoint, grant production eligibility, or place an order. Confirmation
outcomes and production selection remain with their existing independent owners.
