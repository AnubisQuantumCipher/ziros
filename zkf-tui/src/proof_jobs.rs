use std::sync::mpsc::{self, Receiver};

use zkf_lib::{EmbeddedProof, Program, ProofEvent, WitnessInputs};
use zkf_ui::{ProofProgressReporter, ZkTheme, render_credential, render_proof_result};

#[derive(Debug, Clone)]
pub struct DemoProofResult {
    pub proof: EmbeddedProof,
    pub verified: bool,
    pub proof_summary: String,
    pub credential: String,
    pub progress_lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ProofJobUpdate {
    Event(ProofEvent),
    Finished(Box<DemoProofResult>),
    Failed(String),
}

fn public_labels(program: &Program) -> Vec<String> {
    program
        .signals
        .iter()
        .filter(|signal| signal.visibility == zkf_lib::Visibility::Public)
        .map(|signal| signal.name.clone())
        .collect()
}

pub fn run_local_proof_demo(
    program: &Program,
    inputs: &WitnessInputs,
) -> Result<DemoProofResult, String> {
    let theme = ZkTheme::default();
    let mut reporter = ProofProgressReporter::new(true);
    let proof = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        zkf_lib::compile_and_prove_with_progress(program, inputs, None, None, |event| {
            reporter.observe(event);
        })
    })
    .map_err(|err| err.to_string())?;
    let verified =
        zkf_lib::verify(&proof.compiled, &proof.artifact).map_err(|err| err.to_string())?;
    let labels = public_labels(&proof.compiled.program);
    let label_refs = labels.iter().map(String::as_str).collect::<Vec<_>>();

    Ok(DemoProofResult {
        proof_summary: render_proof_result(&proof, &theme),
        credential: render_credential(&proof.artifact.public_inputs, &label_refs, &theme),
        progress_lines: reporter.lines(),
        verified,
        proof,
    })
}

pub fn run_local_proof_demo_with_backend(
    program: &Program,
    inputs: &WitnessInputs,
    backend: &str,
) -> Result<DemoProofResult, String> {
    let theme = ZkTheme::default();
    let mut reporter = ProofProgressReporter::new(true);
    let proof = zkf_lib::compile_and_prove_with_progress_backend(
        program,
        inputs,
        backend,
        None,
        None,
        |event| reporter.observe(event),
    )
    .map_err(|err| err.to_string())?;
    let verified =
        zkf_lib::verify(&proof.compiled, &proof.artifact).map_err(|err| err.to_string())?;
    let labels = public_labels(&proof.compiled.program);
    let label_refs = labels.iter().map(String::as_str).collect::<Vec<_>>();

    Ok(DemoProofResult {
        proof_summary: render_proof_result(&proof, &theme),
        credential: render_credential(&proof.artifact.public_inputs, &label_refs, &theme),
        progress_lines: reporter.lines(),
        verified,
        proof,
    })
}

pub fn spawn_local_proof_job(program: Program, inputs: WitnessInputs) -> Receiver<ProofJobUpdate> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let progress_tx = tx.clone();
        let theme = ZkTheme::default();
        let labels = public_labels(&program);
        let label_refs = labels.iter().map(String::as_str).collect::<Vec<_>>();
        let mut reporter = ProofProgressReporter::new(true);
        let proof =
            match zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                zkf_lib::compile_and_prove_with_progress(&program, &inputs, None, None, |event| {
                    reporter.observe(event.clone());
                    let _ = progress_tx.send(ProofJobUpdate::Event(event));
                })
            }) {
                Ok(proof) => proof,
                Err(err) => {
                    let _ = tx.send(ProofJobUpdate::Failed(err.to_string()));
                    return;
                }
            };
        let verified = match zkf_lib::verify(&proof.compiled, &proof.artifact) {
            Ok(verified) => verified,
            Err(err) => {
                let _ = tx.send(ProofJobUpdate::Failed(err.to_string()));
                return;
            }
        };
        let result = DemoProofResult {
            proof_summary: render_proof_result(&proof, &theme),
            credential: render_credential(&proof.artifact.public_inputs, &label_refs, &theme),
            progress_lines: reporter.lines(),
            verified,
            proof,
        };
        let _ = tx.send(ProofJobUpdate::Finished(Box::new(result)));
    });
    rx
}

pub fn spawn_local_proof_job_with_backend(
    program: Program,
    inputs: WitnessInputs,
    backend: String,
) -> Receiver<ProofJobUpdate> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let progress_tx = tx.clone();
        let theme = ZkTheme::default();
        let labels = public_labels(&program);
        let label_refs = labels.iter().map(String::as_str).collect::<Vec<_>>();
        let mut reporter = ProofProgressReporter::new(true);
        let proof = match zkf_lib::compile_and_prove_with_progress_backend(
            &program,
            &inputs,
            &backend,
            None,
            None,
            |event| {
                reporter.observe(event.clone());
                let _ = progress_tx.send(ProofJobUpdate::Event(event));
            },
        ) {
            Ok(proof) => proof,
            Err(err) => {
                let _ = tx.send(ProofJobUpdate::Failed(err.to_string()));
                return;
            }
        };
        let verified = match zkf_lib::verify(&proof.compiled, &proof.artifact) {
            Ok(verified) => verified,
            Err(err) => {
                let _ = tx.send(ProofJobUpdate::Failed(err.to_string()));
                return;
            }
        };
        let result = DemoProofResult {
            proof_summary: render_proof_result(&proof, &theme),
            credential: render_credential(&proof.artifact.public_inputs, &label_refs, &theme),
            progress_lines: reporter.lines(),
            verified,
            proof,
        };
        let _ = tx.send(ProofJobUpdate::Finished(Box::new(result)));
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn demo_proof_roundtrip_verifies() {
        let template = zkf_lib::templates::poseidon_commitment().expect("template");
        let result =
            run_local_proof_demo(&template.program, &template.sample_inputs).expect("proof demo");
        assert!(result.verified);
        assert!(result.proof_summary.contains("Proof Ready"));
        assert!(result.credential.contains("commitment"));
        assert_eq!(result.progress_lines.len(), 4);
    }

    #[test]
    fn spawned_job_emits_stage_updates_before_finish() {
        let template = zkf_lib::templates::poseidon_commitment().expect("template");
        let receiver =
            spawn_local_proof_job(template.program.clone(), template.sample_inputs.clone());
        let mut stages = Vec::new();
        let mut finished = false;

        while let Ok(update) = receiver.recv_timeout(Duration::from_secs(10)) {
            match update {
                ProofJobUpdate::Event(event) => stages.push(event.stage()),
                ProofJobUpdate::Finished(result) => {
                    assert!(result.verified);
                    finished = true;
                    break;
                }
                ProofJobUpdate::Failed(message) => panic!("proof job failed: {message}"),
            }
        }

        assert!(finished, "proof job never finished");
        stages.dedup();
        assert_eq!(
            stages,
            vec![
                zkf_lib::ProofStage::Compile,
                zkf_lib::ProofStage::Witness,
                zkf_lib::ProofStage::PrepareWitness,
                zkf_lib::ProofStage::Prove,
            ]
        );
    }
}
