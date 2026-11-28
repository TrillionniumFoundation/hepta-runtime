// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Label-free compilation and original-descriptor preparation of both finite alternatives.

use super::*;

pub(super) async fn preflight(
	input: Input,
	authority: &Authority,
	roots: &[PathBuf],
	state: &Path,
) -> Result<Option<Prepared>> {
	let started = std::time::Instant::now();
	authority.authorize(&input)?;
	authority.revalidate().await?;
	let raw = decode_raw(&input.raw_input_hex)?;
	let normal_raw = decode_raw(&input.retention_raw_input_hex)?;
	let normalized = model::inputs(&raw)?;
	let task = model::LateQuoteMinV1::check(&normalized)?;
	let (mut file, before) =
		rea_files::open_confined(Path::new(authority.source_path()), roots).await?;
	let parent = capture(&mut file, &before, authority.parent_sha256()).await?;
	let bound = model::bind(input.profile_json.as_bytes(), &parent, &raw)?;
	let normal = model::bind(
		input.retention_profile_json.as_bytes(),
		&parent,
		&normal_raw,
	)?;
	ensure!(
		bound.canonical_sha256() == authority.parent_sha256()
			&& normal.canonical_sha256() == authority.parent_sha256(),
		"both data profiles must bind the same complete original session checkpoint"
	);
	let evaluator = model::evaluator_identity();
	let Some(program) = model::compile_late_quote(&bound, &parent, &task, &evaluator)? else {
		return Ok(None);
	};
	let parent_state = program.parent(&parent)?;
	let keep = program.apply(&parent_state, &task, false)?;
	let sign = program.apply(&parent_state, &task, true)?;
	let words = |changed| -> Result<Vec<ExactElementEdit>> {
		program
			.scope_words(&parent, changed)?
			.into_iter()
			.map(|(index, before, after)| {
				Ok(ExactElementEdit {
					index: u64::try_from(index)?,
					expected_hex: hex(&before.to_le_bytes()),
					replacement_hex: hex(&after.to_le_bytes()),
				})
			})
			.collect()
	};
	let sign_words = words(true)?;
	let pairs = sign_words
		.iter()
		.map(|word| {
			Ok((
				represented_value("F32", &word.expected_hex)?,
				represented_value("F32", &word.replacement_hex)?,
			))
		})
		.collect::<Result<Vec<_>>>()?;
	let sign_admissible =
		crate::mcp::weight_norm::check_pairs(pairs, input.maximum_update_l2_norm)?.within_budget;
	let plan = Plan {
		schema: "hepta.late-quote.sealed-plan.v1".into(),
		input,
		authority: authority.binding()?,
		roots: roots.to_vec(),
		state: state.to_owned(),
		transaction_implementation: implementation(),
		cohort_implementation: cohort_implementation(),
		evaluator_source: evaluator,
		running_executable_sha256: running_executable_sha256().await?,
		budget: budget(),
		semantic_task: task.evidence(),
		program: program.evidence(),
		parent_function: parent_state.identity().clone(),
		keep_function: keep.identity().clone(),
		sign_function: sign.identity().clone(),
		keep_words: words(false)?,
		sign_words,
		sign_admissible,
	};
	let keep = prepare_with_roots(
		plan.request(Action::Keep)?,
		roots,
		None,
		None,
		Some(plan.function_binding(Action::Keep, false)?),
	)
	.await?;
	let sign = if plan.sign_admissible {
		Some(
			prepare_with_roots(
				plan.request(Action::Sign)?,
				roots,
				None,
				None,
				Some(plan.function_binding(Action::Sign, false)?),
			)
			.await?,
		)
	} else {
		None
	};
	ensure!(
		keep.manifest.target_sha256 == plan.keep_function.artifact_sha256
			&& sign
				.as_ref()
				.is_none_or(|c| c.manifest.target_sha256 == plan.sign_function.artifact_sha256),
		"cohort complete-byte transforms differ from the native semantic program"
	);
	authority.revalidate().await?;
	Ok(Some(Prepared {
		plan,
		parent,
		keep,
		sign,
		preparation_wall_seconds: started.elapsed().as_secs_f64(),
	}))
}
