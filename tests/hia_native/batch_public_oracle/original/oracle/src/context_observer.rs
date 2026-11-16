
// Additive read-only observer; the original task-local implementation above is intact.
pub fn observe_context() -> serde_json::Value {
    CTX.try_with(|ctx| serde_json::json!({"present":true,"hints":ctx.hints.borrow().clone()}))
        .unwrap_or_else(|_|serde_json::json!({"present":false,"hints":[]}))
}
