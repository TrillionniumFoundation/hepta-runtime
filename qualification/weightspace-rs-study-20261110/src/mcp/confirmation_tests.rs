// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::mcp::projection::{plan, Policy, Program};
fn base() -> FrozenTensor { FrozenTensor::new("head",1,2,vec![1.,1.],&digest(b"fixture")).unwrap() }
fn data(role:Role, scale:f32, target:f32, regression_input:Vec<f32>) -> Partition {
 Partition::new(role,vec![Example {id:format!("p{scale}"),input:vec![scale,0.],target:vec![target],regression:false},Example {id:format!("r{scale}"),input:regression_input,target:vec![0.],regression:true}]).unwrap()
}
fn candidate(b:&FrozenTensor,p:&Protocol) -> Candidate {
 plan(b,&b.binding(p.sha256()),&Program::SparseColumnProjection {columns:vec![0],unit_direction:vec![1.],alpha:1.},&Policy {max_abs_delta:2.,max_update_l2:2.,..Policy::default()}).unwrap()
}
#[test]
fn accepted_preview_retains_immutable_base_and_valid_evidence_chain() {
 let b=base();let cal=data(Role::Calibration,1.,0.,vec![0.,1.]);let hold=data(Role::Confirmation,2.,0.,vec![0.,2.]);
 let p=Protocol::freeze(&b,&cal,&hold,0.1,0.).unwrap();let c=candidate(&b,&p);let mut broker=SplitUseBroker::new(&b);
 let r=broker.confirm(&b,&c,&p,&cal,&hold).unwrap();assert!(r.accepted);assert_eq!(broker.preview_pointer(),c.sha256());assert_eq!(b.values(),&[1.,1.]);
 assert_eq!(r.report["independent_holdout_verified"],false);assert_eq!(r.report["production_eligible"],false);broker.verify_chain().unwrap();
}
#[test]
fn failed_quality_gate_restores_preview_and_burns_confirmation_rows() {
 let b=base();let cal=data(Role::Calibration,1.,0.,vec![0.,1.]);let hold=data(Role::Confirmation,2.,2.,vec![0.,2.]);
 let p=Protocol::freeze(&b,&cal,&hold,0.1,0.).unwrap();let c=candidate(&b,&p);let mut broker=SplitUseBroker::new(&b);
 let r=broker.confirm(&b,&c,&p,&cal,&hold).unwrap();assert!(!r.accepted);assert!(r.rollback_verified);assert_eq!(broker.preview_pointer(),b.sha256());
 assert!(broker.confirm(&b,&c,&p,&cal,&hold).unwrap_err().to_string().contains("reuse"));broker.verify_chain().unwrap();
}
#[test]
fn primary_improvement_cannot_hide_regression() {
 let b=base();let cal=data(Role::Calibration,1.,0.,vec![0.,1.]);let hold=data(Role::Confirmation,2.,0.,vec![0.5,2.]);
 let p=Protocol::freeze(&b,&cal,&hold,0.1,0.).unwrap();let c=candidate(&b,&p);let mut broker=SplitUseBroker::new(&b);
 let r=broker.confirm(&b,&c,&p,&cal,&hold).unwrap();assert!(!r.accepted);assert!(r.rollback_verified);assert_eq!(r.report["scores"]["confirmation"]["mean_primary_gain"],4.);
}
#[test]
fn relabeling_does_not_disguise_reused_inputs_or_changed_partition() {
 let b=base();let cal=data(Role::Calibration,1.,0.,vec![0.,1.]);let mut rows=cal.examples.clone();for r in &mut rows {r.id.push_str("alias");r.target[0]=99.;}
 let duplicate=Partition::new(Role::Confirmation,rows).unwrap();assert!(Protocol::freeze(&b,&cal,&duplicate,0.,0.).is_err());
 let hold=data(Role::Confirmation,2.,0.,vec![0.,2.]);let p=Protocol::freeze(&b,&cal,&hold,0.,0.).unwrap();let c=candidate(&b,&p);let mut broker=SplitUseBroker::new(&b);
 let other=data(Role::Confirmation,3.,0.,vec![0.,3.]);assert!(broker.confirm(&b,&c,&p,&cal,&other).is_err());
}
#[test]
fn incomplete_schema_fails_and_candidate_is_not_selected() {
 let b=base();let cal=data(Role::Calibration,1.,0.,vec![0.,1.]);let mut hold=data(Role::Confirmation,2.,0.,vec![0.,2.]);hold.examples[0].input.pop();
 let hold=Partition::new(Role::Confirmation,hold.examples).unwrap();let p=Protocol::freeze(&b,&cal,&hold,0.,0.).unwrap();let c=candidate(&b,&p);let mut broker=SplitUseBroker::new(&b);
 let r=broker.confirm(&b,&c,&p,&cal,&hold).unwrap();assert!(r.rollback_verified);assert!(r.report["scores"]["confirmation_error"].as_str().unwrap().contains("complete"));
}
