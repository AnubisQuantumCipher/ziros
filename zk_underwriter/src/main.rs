use zkf_dsl::circuit;
use k256::ecdsa::{SigningKey, Signature, signature::Signer};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use num_bigint::BigInt;
use num_traits::Num;

#[circuit(field = "bn254")]
fn verify_credit_score(
    pk_x: Public<Field>,
    pk_y: Public<Field>,
    sig_r: Private<Field>,
    sig_s: Private<Field>,
    msg_hash: Private<Field>,
    score: Private<u32>,
) {
    ecdsa_verify(pk_x, pk_y, sig_r, sig_s, msg_hash);
    assert_eq(msg_hash, score as Field);
    assert_range(score, 10);
    let diff = score - 700;
    assert_range(diff, 10);
}

fn to_decimal(hex_str: &str) -> String {
    BigInt::from_str_radix(hex_str, 16).unwrap().to_str_radix(10)
}

fn main() {
    println!("=== ZK-Underwriter: Generating Signed Credential ===");
    
    let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let verifying_key = signing_key.verifying_key();
    let encoded_pk = verifying_key.to_encoded_point(false);
    let px = hex::encode(encoded_pk.x().unwrap());
    let py = hex::encode(encoded_pk.y().unwrap());
    
    let score = 750u32;
    let msg = score.to_be_bytes();
    let signature: Signature = signing_key.sign(&msg);
    let r = hex::encode(signature.r().to_bytes());
    let s = hex::encode(signature.s().to_bytes());

    let zir = verify_credit_score_program();
    let program = zkf_core::program_zir_to_v2(&zir).unwrap();
    
    let inputs = verify_credit_score_inputs(
        &to_decimal(&px),
        &to_decimal(&py),
        &to_decimal(&r),
        &to_decimal(&s),
        &score.to_string(),
        &score.to_string()
    );

    std::fs::write("underwriter.ir.json", serde_json::to_string_pretty(&program).unwrap()).unwrap();
    std::fs::write("inputs.json", serde_json::to_string_pretty(&inputs).unwrap()).unwrap();
    
    println!("Underwriter circuit and decimal inputs generated!");
}
