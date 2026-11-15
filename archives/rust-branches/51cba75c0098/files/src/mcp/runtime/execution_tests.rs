// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contract-level tests of the remote non-effectful ABI.

use super::*;

fn digest(byte: char) -> String {
	byte.to_string().repeat(64)
}

fn fixture() -> CanonicalExecutionRecordV1 {
	CanonicalExecutionRecordV1::ExecutionIntent(CanonicalExecutionIntentV1 {
		binding: CanonicalExecutionBindingV1 {
			schema_version: 1,
			run_id: "run-1".into(),
			turn_id: "turn-1".into(),
			cell_id: Some("cell-1".into()),
			organ_id: None,
			operation_id: "op-1".into(),
			principal: "agent-1".into(),
			objective_digest: digest('1'),
			policy_digest: digest('2'),
			candidate_digest: digest('3'),
			host: "host-1".into(),
			generation: 1,
			idempotency_key: "idem-1".into(),
			predecessor: None,
			currentness: CanonicalCurrentnessV1::Current,
			final_use: ShadowFinalUseV1::NotGranted,
			rollback_reference: None,
		},
		class: CanonicalExecutionClassV1::ReadOnlyInspection,
		payload_digest: digest('6'),
	})
}

#[test]
fn shadow_abi_json_roundtrip_and_deny_unknown_fields() {
	let value = fixture();
	let bytes = serde_json::to_vec(&value).unwrap();
	let restored: CanonicalExecutionRecordV1 = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
	assert_eq!(
		validate_and_digest(&restored).unwrap(),
		"9ef6afcc1658e9d022a321e0d2decaac71445433c96591a7c1c9afbc5b07f9a9"
	);
	let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
	changed["record"]["binding"]["untrusted"] = serde_json::json!(true);
	assert!(serde_json::from_value::<CanonicalExecutionRecordV1>(changed).is_err());
}

#[test]
fn shadow_abi_denies_noncurrent_drift_and_unrehearsed_mutation() {
	let mut v = fixture();
	let CanonicalExecutionRecordV1::ExecutionIntent(intent) = &mut v;
	intent.binding.generation = 0;
	assert!(validate_and_digest(&v).is_err());
	let CanonicalExecutionRecordV1::ExecutionIntent(intent) = &mut v;
	intent.binding.generation = 1;
	intent.class = CanonicalExecutionClassV1::DurableProcess;
	assert!(validate_and_digest(&v).is_err());
	let CanonicalExecutionRecordV1::ExecutionIntent(intent) = &mut v;
	intent.binding.rollback_reference = Some("rollback-1".into());
	assert!(validate_and_digest(&v).is_ok());
	let CanonicalExecutionRecordV1::ExecutionIntent(intent) = &mut v;
	intent.binding.predecessor = Some(digest('a'));
	assert!(validate_and_digest(&v).is_err());
}

#[test]
fn shadow_abi_denies_stale_intent_and_fake_final_use() {
	let mut value = serde_json::to_value(fixture()).unwrap();
	value["record"]["binding"]["currentness"] = serde_json::json!("stale");
	let stale: CanonicalExecutionRecordV1 = serde_json::from_value(value.clone()).unwrap();
	assert!(validate_and_digest(&stale).is_err());
	value["record"]["binding"]["currentness"] = serde_json::json!("current");
	value["record"]["binding"]["final_use"] =
		serde_json::json!({"state": "verified", "grant_digest": digest('4')});
	assert!(serde_json::from_value::<CanonicalExecutionRecordV1>(value).is_err());
}

#[test]
fn shadow_abi_refuses_unknown_fields_at_every_tagged_envelope() {
    let canonical = serde_json::to_value(fixture()).unwrap();

    // A tagged record must not silently drop an injected field and later
    // compute the same digest as a different wire payload.
    let mut extra_record = canonical.clone();
    extra_record["opaque_authority"] = serde_json::json!("forged");
    assert!(
        serde_json::from_value::<CanonicalExecutionRecordV1>(extra_record).is_err(),
        "unknown record envelope field was silently discarded"
    );

    // The unit final_use variant is never evidence of authorization. Reject
    // claims smuggled alongside the valid not_granted tag.
    let mut extra_final_use = canonical.clone();
    extra_final_use["record"]["binding"]["final_use"]["grant_digest"] =
        serde_json::json!(digest('4'));
    assert!(
        serde_json::from_value::<CanonicalExecutionRecordV1>(extra_final_use).is_err(),
        "unknown FinalUse fields must not be accepted"
    );
}
