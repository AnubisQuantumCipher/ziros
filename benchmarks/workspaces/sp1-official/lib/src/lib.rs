use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WorkloadInput {
    pub kind: u32,
    pub values: [u32; 8],
}

pub fn compute_result(input: &WorkloadInput) -> u32 {
    match input.kind {
        0 => input.values[0].saturating_mul(input.values[1]),
        1 => {
            let left = &input.values[..4];
            let right = &input.values[4..8];
            left.iter()
                .zip(right.iter())
                .map(|(a, b)| a.saturating_mul(*b))
                .sum()
        }
        2 => {
            let mut a = input.values[0];
            let mut b = input.values[1];
            for _ in 0..8 {
                let next = a.saturating_add(b);
                a = b;
                b = next;
            }
            b
        }
        _ => 0,
    }
}
