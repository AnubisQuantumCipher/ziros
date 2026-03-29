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
