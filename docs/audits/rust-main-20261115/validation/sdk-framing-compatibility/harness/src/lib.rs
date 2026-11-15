#![allow(dead_code)]
// Focused compilation of actual repository modules; no transport or SDK substitute.
pub mod mcp {
    #[path = "/workspace/scratch/d72683e5e62a/runtime-transport-fix/src/mcp/rea_inline_order.rs"]
    pub mod rea_inline_order;
    #[path = "/workspace/scratch/d72683e5e62a/runtime-transport-fix/src/mcp/rea_mcp_transport.rs"]
    pub mod rea_mcp_transport;
    #[path = "/workspace/scratch/d72683e5e62a/runtime-transport-fix/src/mcp/rea_structured_wire.rs"]
    pub mod rea_structured_wire;
    #[path = "/workspace/scratch/d72683e5e62a/runtime-transport-eof-validation/harness/src/rea_evidence.rs"]
    pub mod rea_evidence;
    #[path = "/workspace/scratch/d72683e5e62a/runtime-transport-eof-validation/harness/src/rea_contract.rs"]
    pub mod rea_contract;
}
