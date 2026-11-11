// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use anyhow::Result;
use hepta_weightspace_audit::mcp::{confirmation::{Example,Partition,Protocol,Role,SplitUseBroker},projection::{digest,plan,FrozenTensor,Policy,Program}};
use serde_json::{json,Value};
use std::{fs::{self,OpenOptions},io::Write,path::Path};
fn partition(role:Role,x:f32,target:f32,regression_x:f32)->Result<Partition> {
 Partition::new(role,vec![Example {id:format!("primary-{x}"),input:vec![x,0.],target:vec![target],regression:false},Example {id:format!("regression-{x}"),input:vec![regression_x,x],target:vec![x],regression:true}])
}
fn retain(path:&Path,value:&Value)->Result<()> {
 let mut f=OpenOptions::new().write(true).create_new(true).open(path)?;
 f.write_all(&serde_json::to_vec_pretty(value)?)?;f.write_all(b"\n")?;f.sync_all()?;Ok(())
}
fn main()->Result<()> {
 let output=std::env::args().nth(1).ok_or_else(||anyhow::anyhow!("usage: projection-demo NEW_OUTPUT_DIRECTORY"))?;
 let root=Path::new(&output);fs::create_dir(root)?;
 let base=FrozenTensor::new("continuation.weight",1,2,vec![1.,1.],&digest(b"synthetic immutable file"))?;
 retain(&root.join("base.json"),&json!({"sha256":base.sha256(),"schema_sha256":base.schema_sha256(),"f32_values":base.values(),"data_class":"synthetic_fixture_only"}))?;
 let mut results=Vec::new();
 for (name,target,regression) in [("known_repair",0.,0.),("quality_rejection",2.,0.),("regression_rejection",0.,0.5)] {
  let calibration=partition(Role::Calibration,1.,0.,0.)?;let confirmation=partition(Role::Confirmation,2.,target,regression)?;
  let protocol=Protocol::freeze(&base,&calibration,&confirmation,0.1,0.)?;
  let candidate=plan(&base,&base.binding(protocol.sha256()),&Program::SparseColumnProjection {columns:vec![0],unit_direction:vec![1.],alpha:1.},&Policy {max_abs_delta:2.,max_update_l2:2.,..Policy::default()})?;
  let mut broker=SplitUseBroker::new(&base);let outcome=broker.confirm(&base,&candidate,&protocol,&calibration,&confirmation)?;broker.verify_chain()?;
  let replay=broker.confirm(&base,&candidate,&protocol,&calibration,&confirmation).err().map(|e|e.to_string());
  let result=json!({"case":name,"outcome":outcome,"replay_refusal":replay,"base_still_exact":base.values()==[1.,1.],"candidate_values":candidate.values(),"candidate_sha256":candidate.sha256(),"protocol":protocol});
  retain(&root.join(format!("{name}-patch.json")),candidate.receipt())?;
  retain(&root.join(format!("{name}-events.json")),&serde_json::to_value(broker.events())?)?;
  retain(&root.join(format!("{name}-result.json")),&result)?;results.push(result);
 }
 let report=json!({"scope":"software/contract demonstration on synthetic linear fixtures; no model efficacy experiment","upstream_source_commit":"bc38fb82244b946907886704b3c677bf00761cb9","gradient_steps":0,"production_eligible":false,"live_checkpoint_modified":false,"split_reuse_prevention_durable":false,"results":results});
 retain(&root.join("report.json"),&report)?;println!("{}",serde_json::to_string_pretty(&report)?);Ok(())
}
