// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

pub(crate) fn severity_rank(severity: &str) -> u8 {
    match severity {
        "moderate" => 1,
        "high" => 2,
        "critical" => 3,
        "model-integrity-critical" => 4,
        _ => 0,
    }
}

pub(crate) fn two_thirds_accepts(accepted_count: usize, total_count: usize) -> bool {
    let total = total_count.max(1);
    accepted_count.saturating_mul(3) >= total.saturating_mul(2)
}

#[cfg(test)]
mod tests {
    use super::{severity_rank, two_thirds_accepts};

    #[test]
    fn threshold_requires_two_thirds() {
        assert!(two_thirds_accepts(2, 3));
        assert!(!two_thirds_accepts(2, 4));
    }

    #[test]
    fn severity_order_is_monotone() {
        assert!(severity_rank("critical") > severity_rank("moderate"));
    }
}
