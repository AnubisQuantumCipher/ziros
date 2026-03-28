#![no_main]

sp1_zkvm::entrypoint!(main);

use zkf_metal_public_proof_lib::{
    BundleWitness, GuestBundleWitness, expected_public_values, validate_bundle_evidence,
};

pub fn main() {
    let witness = BundleWitness::from(sp1_zkvm::io::read::<GuestBundleWitness>());
    let bundle_evidence_digest =
        validate_bundle_evidence(&witness).expect("bundle evidence validation");
    let public_values = expected_public_values(
        &witness.statement_bundle_digest,
        &witness.private_source_commitment_root,
        &witness.metallib_digest_set_root,
        &witness.attestation_manifest_digest,
        &witness.toolchain_identity_digest,
        &bundle_evidence_digest,
    )
    .expect("expected public values");
    sp1_zkvm::io::commit_slice(public_values.as_slice());
}
