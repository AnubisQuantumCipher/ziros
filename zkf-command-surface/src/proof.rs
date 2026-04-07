use crate::types::{CommandEventKindV1, CommandEventV1};
use serde_json::json;
use zkf_lib::app::progress::ProofEvent;

pub fn proof_event_to_command_event(action_id: &str, event: ProofEvent) -> CommandEventV1 {
    match event {
        ProofEvent::StageStarted { stage } => {
            let mut command_event = CommandEventV1::new(
                action_id,
                CommandEventKindV1::Progress,
                format!("{} started", stage.label()),
            );
            command_event.stage = Some(stage.label().to_string());
            command_event
        }
        ProofEvent::CompileCompleted {
            backend,
            signal_count,
            constraint_count,
            duration_ms,
        } => {
            let mut command_event = CommandEventV1::new(
                action_id,
                CommandEventKindV1::Progress,
                format!("compile completed on {}", backend.as_str()),
            );
            command_event.stage = Some("compile".to_string());
            command_event.metrics = Some(json!({
                "backend": backend.as_str(),
                "signal_count": signal_count,
                "constraint_count": constraint_count,
                "duration_ms": duration_ms,
            }));
            command_event
        }
        ProofEvent::WitnessCompleted {
            witness_values,
            duration_ms,
        } => {
            let mut command_event = CommandEventV1::new(
                action_id,
                CommandEventKindV1::Progress,
                "witness completed",
            );
            command_event.stage = Some("witness".to_string());
            command_event.metrics = Some(json!({
                "witness_values": witness_values,
                "duration_ms": duration_ms,
            }));
            command_event
        }
        ProofEvent::PrepareWitnessCompleted {
            witness_values,
            public_inputs,
            duration_ms,
        } => {
            let mut command_event = CommandEventV1::new(
                action_id,
                CommandEventKindV1::Progress,
                "constraint preparation completed",
            );
            command_event.stage = Some("prepare-witness".to_string());
            command_event.metrics = Some(json!({
                "witness_values": witness_values,
                "public_inputs": public_inputs,
                "duration_ms": duration_ms,
            }));
            command_event
        }
        ProofEvent::ProveCompleted {
            backend,
            proof_size_bytes,
            duration_ms,
        } => {
            let mut command_event = CommandEventV1::new(
                action_id,
                CommandEventKindV1::Completed,
                format!("proof completed on {}", backend.as_str()),
            );
            command_event.stage = Some("prove".to_string());
            command_event.metrics = Some(json!({
                "backend": backend.as_str(),
                "proof_size_bytes": proof_size_bytes,
                "duration_ms": duration_ms,
            }));
            command_event
        }
    }
}
