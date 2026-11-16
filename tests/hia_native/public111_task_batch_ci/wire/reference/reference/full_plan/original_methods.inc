impl OctofsServer {
	async fn weight_bellman_plan(
		&self,
		Parameters(params): Parameters<weight_bellman::BellmanPlanParams>,
	) -> Result<String, String> {
		weight_bellman::plan(params)
			.await
			.map_err(|error| error.to_string())
	}

}
