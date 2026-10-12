//! Additive identities; original Goal/Candidate/receipt bytes remain unchanged.
use flypow_target_protocol::{self as p, CandidateInput, GoalSpec, Result};
use serde_json::{json, Value};
pub fn simulation(g: &GoalSpec, x: &CandidateInput, seed: &str) -> Result<(String, Value)> {
    g.validate_input(x)?;
    if seed.len() != 16 {
        return Err("seed width".into());
    }
    p::unhex(seed)?;
    let v = json!({"schema":"flybrain-simulation-v1","sourceRoot":g.source_root,"registryRoot":g.registry_root,"graphRoot":g.graph_root,"modelRoot":g.model_root,"modelDataRoot":g.model_data_root,"parameterProfileHash":g.parameter_profile_hash,"numericalRules":p::parameters(),"initialState":"zero-membrane-no-prior-events-v0","backgroundGenerator":"sim-core-development-v0-seeded","input":x,"seedHex":seed,"timeStepUs":g.time_step_us,"startStep":0,"steps":g.steps});
    Ok((p::id("science-simulation-v1", &v)?, v))
}
pub fn task(g: &GoalSpec) -> Result<String> {
    p::id(
        "science-task-v1",
        &json!({"graphRoot":g.graph_root,"modelRoot":g.model_root,"parameterProfileHash":g.parameter_profile_hash,"inputDomainHash":g.input_domain_hash,"stimulusSetRoot":g.stimulus_set_root,"responseSetRoot":g.response_set_root,"offTargetSetRoot":g.off_target_set_root,"windows":g.windows,"evaluatorVersion":g.evaluator_version,"maxStimulusCost":g.max_stimulus_cost,"steps":g.steps,"timeStepUs":g.time_step_us}),
    )
}
pub fn readout(g: &GoalSpec, simulations: &[String]) -> Result<(String, Value)> {
    let mut ids = simulations.to_vec();
    ids.sort();
    ids.dedup();
    if ids.len() != simulations.len() {
        return Err("duplicate background identities".into());
    }
    let v = json!({"schema":"flybrain-readout-v1","simulationIds":ids,"responseSetRoot":g.response_set_root,"offTargetSetRoot":g.off_target_set_root,"windows":g.windows,"evaluatorVersion":g.evaluator_version,"maxStimulusCost":g.max_stimulus_cost,"inputDomainHash":g.input_domain_hash});
    Ok((p::id("science-readout-v1", &v)?, v))
}
pub fn contribution(
    actor: &str,
    kind: &str,
    science: &str,
    task: &str,
    plan: &str,
    authorization: &str,
) -> Result<String> {
    p::root(actor)?;
    p::root(science)?;
    p::root(task)?;
    p::id(
        "contribution-v1",
        &json!({"schema":"flybrain-contribution-v1","actor":actor,"kind":kind,"scienceId":science,"taskId":task,"budgetPlan":plan,"authorization":authorization}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_ignores_miner_goal_labels_and_readout() {
        let mut g: GoalSpec = serde_json::from_str(include_str!(
            "../web/data/target-mining-v2/product-group-1-20261011/goal.json"
        ))
        .unwrap();
        let x = CandidateInput {
            stimulated_body_id: "87973".into(),
            start_step: 0,
            end_step: 1,
            current: 150,
        };
        let first = simulation(&g, &x, "74ae3c5e928f289c").unwrap().0;
        let t = task(&g).unwrap();
        g.description = "renamed".into();
        g.family = "display only in this test".into();
        assert_eq!(t, task(&g).unwrap());
        assert_eq!(first, simulation(&g, &x, "74ae3c5e928f289c").unwrap().0);
        g.response_set_root = "a".repeat(64);
        assert_eq!(first, simulation(&g, &x, "74ae3c5e928f289c").unwrap().0);
        assert_ne!(t, task(&g).unwrap());
        assert_ne!(first, simulation(&g, &x, "74ae3c5e928f289d").unwrap().0);
    }
}
