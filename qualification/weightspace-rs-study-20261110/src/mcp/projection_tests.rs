// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use super::*;
fn base() -> FrozenTensor { FrozenTensor::new("continuation.weight",2,3,vec![1.,2.,3.,4.,5.,6.],&digest(b"fixture source")).unwrap() }
fn policy() -> Policy { Policy { max_abs_delta:100.,max_update_l2:100.,..Policy::default() } }
fn program() -> Program { Program::SparseColumnProjection { columns:vec![1],unit_direction:vec![1.,0.],alpha:1. } }
fn binding(b:&FrozenTensor) -> Binding { b.binding(&digest(b"frozen protocol")) }
#[test]
fn projection_uses_immutable_base_and_exact_native_edit_bytes() {
 let b=base();let before=b.values().to_vec();let c=plan(&b,&binding(&b),&program(),&policy()).unwrap();
 assert_eq!(b.values(),before);assert_eq!(c.values(),&[1.,0.,3.,4.,5.,6.]);
 assert_eq!(c.edits().len(),1);assert_eq!(c.edits()[0].index,1);
 assert_eq!(c.edits()[0].expected_hex,"00000040");assert_eq!(c.edits()[0].replacement_hex,"00000000");
 assert_eq!(c.receipt()["gradient_steps"],0);assert_eq!(c.receipt()["production_eligible"],false);
 assert_eq!(c.receipt()["source_file_authenticated_here"],false);
}
#[test]
fn direction_sign_is_invariant_and_alpha_six_is_reflection_amplification() {
 let b=base();let a=plan(&b,&binding(&b),&program(),&policy()).unwrap();
 let negative=Program::SparseColumnProjection {columns:vec![1],unit_direction:vec![-1.,0.],alpha:1.};
 assert_eq!(a.values(),plan(&b,&binding(&b),&negative,&policy()).unwrap().values());
 let six=Program::SparseColumnProjection {columns:vec![1],unit_direction:vec![1.,0.],alpha:6.};
 assert_eq!(plan(&b,&binding(&b),&six,&policy()).unwrap().values()[1],-10.);
}
#[test]
fn stale_source_tensor_schema_and_protocol_fail() {
 let b=base();
 for field in 0..4 { let mut x=binding(&b);match field {0=>x.source_file_sha256=digest(b"other"),1=>x.tensor_sha256=digest(b"other"),2=>x.schema_sha256=digest(b"other"),_=>x.protocol_sha256="bad".into()};assert!(plan(&b,&x,&program(),&policy()).is_err()); }
 let c=plan(&b,&binding(&b),&program(),&policy()).unwrap();assert!(c.revalidate(&b,&digest(b"other protocol")).is_err());
}
#[test]
fn protected_tensor_rejects_both_operations() {
 let b=base();let mut p=policy();p.protected_tensors.insert("continuation.weight".into());
 assert!(plan(&b,&binding(&b),&program(),&p).is_err());
 let coords=Program::Coordinates {edits:vec![Coordinate {index:0,expected_f32_bits:1f32.to_bits(),replacement:0.}]};
 assert!(plan(&b,&binding(&b),&coords,&p).is_err());
}
#[test]
fn malformed_direction_columns_and_dose_are_rejected() {
 let b=base();let cases=[
 Program::SparseColumnProjection {columns:vec![1,1],unit_direction:vec![1.,0.],alpha:1.},
 Program::SparseColumnProjection {columns:vec![3],unit_direction:vec![1.,0.],alpha:1.},
 Program::SparseColumnProjection {columns:vec![1],unit_direction:vec![2.,0.],alpha:1.},
 Program::SparseColumnProjection {columns:vec![1],unit_direction:vec![f64::NAN,0.],alpha:1.},
 Program::SparseColumnProjection {columns:vec![1],unit_direction:vec![1.],alpha:1.},
 Program::SparseColumnProjection {columns:vec![1],unit_direction:vec![1.,0.],alpha:f64::INFINITY},
 Program::SparseColumnProjection {columns:vec![1],unit_direction:vec![1.,0.],alpha:9.},
 ];for p in cases { assert!(plan(&b,&binding(&b),&p,&policy()).is_err()); }
}
#[test]
fn exact_stored_f32_joint_and_coordinate_budgets_have_no_epsilon_escape() {
 let b=FrozenTensor::new("head",1,2,vec![0.,0.],&digest(b"base")).unwrap();
 let edits=Program::Coordinates {edits:vec![Coordinate {index:0,expected_f32_bits:0,replacement:3.},Coordinate {index:1,expected_f32_bits:0,replacement:4.}]};
 let mut p=policy();p.max_update_l2=5.;assert!(plan(&b,&binding(&b),&edits,&p).is_ok());
 p.max_update_l2=5f64.next_down();assert!(plan(&b,&binding(&b),&edits,&p).is_err());
 p.max_update_l2=5.;p.max_abs_delta=4f64.next_down();assert!(plan(&b,&binding(&b),&edits,&p).is_err());
}
#[test]
fn nonfinite_base_shape_coordinates_and_expected_bytes_fail() {
 assert!(FrozenTensor::new("x",1,1,vec![f32::NAN],&digest(b"x")).is_err());
 assert!(FrozenTensor::new("x",2,2,vec![0.],&digest(b"x")).is_err());
 let b=base();for e in [Coordinate {index:0,expected_f32_bits:0,replacement:1.},Coordinate {index:0,expected_f32_bits:1f32.to_bits(),replacement:f32::NAN},Coordinate {index:99,expected_f32_bits:0,replacement:1.}] {
 assert!(plan(&b,&binding(&b),&Program::Coordinates {edits:vec![e]},&policy()).is_err()); }
}
#[test]
fn duplicate_coordinates_and_storage_noops_are_rejected() {
 let b=base();let e=Coordinate {index:0,expected_f32_bits:1f32.to_bits(),replacement:0.};
 assert!(plan(&b,&binding(&b),&Program::Coordinates {edits:vec![e.clone(),e]},&policy()).is_err());
 let p=Program::SparseColumnProjection {columns:vec![1],unit_direction:vec![1.,0.],alpha:0.};
 assert!(plan(&b,&binding(&b),&p,&policy()).is_err());
}
#[test]
fn f32_projection_overflow_is_rejected_before_emitting_an_edit() {
 let b=FrozenTensor::new("head",1,1,vec![f32::MAX],&digest(b"max")).unwrap();
 let p=Program::SparseColumnProjection {columns:vec![0],unit_direction:vec![1.],alpha:8.};
 assert!(plan(&b,&binding(&b),&p,&policy()).is_err());
}
#[test]
fn oversized_projection_is_not_silently_split_into_nonatomic_patches() {
 let b=FrozenTensor::new("head",1024,2,vec![1.;2048],&digest(b"wide")).unwrap();
 let mut u=vec![0.;1024];u[0]=1.;let p=Program::SparseColumnProjection {columns:vec![0,1],unit_direction:u,alpha:1.};
 assert!(plan(&b,&binding(&b),&p,&policy()).unwrap_err().to_string().contains("atomic"));
}
#[test]
fn receipts_cannot_mutate_retained_private_candidate() {
 let b=base();let c=plan(&b,&binding(&b),&program(),&policy()).unwrap();
 let mut report=c.receipt().clone();report["candidate_tensor_sha256"]=json!("forged");
 assert!(c.revalidate(&b,&binding(&b).protocol_sha256).is_ok());assert_ne!(report,c.receipt().clone());
}

#[test]
fn same_tensor_in_a_different_source_file_cannot_reuse_candidate_binding() {
 let b=base();let c=plan(&b,&binding(&b),&program(),&policy()).unwrap();
 let other=FrozenTensor::new("continuation.weight",2,3,b.values().to_vec(),&digest(b"different source file")).unwrap();
 assert_eq!(b.sha256(),other.sha256());assert!(c.revalidate(&other,&binding(&b).protocol_sha256).is_err());
}
