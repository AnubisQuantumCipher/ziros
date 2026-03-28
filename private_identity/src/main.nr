use std;

fn main(
    identity_commitment: Field,
    age: u32,
    salary: u64,
    age_threshold: pub u32,
    salary_threshold: pub u64
) -> pub Field {
    // 1. Verify KYC attributes without revealing them
    assert(age >= age_threshold);
    assert(salary >= salary_threshold);

    // 2. Reconstruct the hash and return it as a public identity record
    std::hash::pedersen_hash([identity_commitment, age as Field, salary as Field])
}
