//! Cost model for deciding whether distributed execution is profitable.

/// Estimate transfer time in milliseconds for a given byte count and bandwidth.
///
/// `bandwidth_gbps`: link bandwidth in gigabits per second.
/// Thunderbolt 5 = 80 Gbps, 10GbE = 10 Gbps.
pub fn transfer_cost_ms(bytes: usize, bandwidth_gbps: f64) -> f64 {
    if bandwidth_gbps <= 0.0 {
        return f64::MAX;
    }
    let bits = bytes as f64 * 8.0;
    let gbits = bits / 1e9;
    let seconds = gbits / bandwidth_gbps;
    seconds * 1000.0
}

/// Rough compute cost in abstract work units.
/// This is intentionally coarse — used for relative comparison only.
pub fn compute_cost_units(constraint_count: usize) -> u64 {
    // Roughly: 1 work unit per constraint, with a small overhead floor.
    constraint_count.max(1) as u64
}

/// Decide whether distributing a partition is profitable.
///
/// Distribution is profitable when the compute savings from parallel execution
/// outweigh the transfer overhead. The heuristic:
///   profitable if transfer_cost < 2 × compute_savings
///
/// Arguments:
/// - `compute_units`: estimated work units for this partition
/// - `boundary_bytes`: total bytes in boundary buffers that must be transferred
/// - `bandwidth_gbps`: link bandwidth
/// - `local_throughput_units_per_ms`: how fast the coordinator can process work units
pub fn is_distribution_profitable(
    compute_units: u64,
    boundary_bytes: usize,
    bandwidth_gbps: f64,
    local_throughput_units_per_ms: f64,
) -> bool {
    if compute_units == 0 || local_throughput_units_per_ms <= 0.0 {
        return false;
    }

    let transfer_ms = transfer_cost_ms(boundary_bytes, bandwidth_gbps);
    let compute_ms = compute_units as f64 / local_throughput_units_per_ms;

    // Distribution saves `compute_ms` but costs `transfer_ms` (send + recv).
    // Require at least 2× payoff to account for overhead.
    transfer_ms < compute_ms / 2.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_cost_thunderbolt5() {
        // 100 MB over 80 Gbps TB5 ≈ 10 ms
        let ms = transfer_cost_ms(100 * 1024 * 1024, 80.0);
        assert!(ms < 15.0, "expected < 15ms, got {ms}");
        assert!(ms > 5.0, "expected > 5ms, got {ms}");
    }

    #[test]
    fn transfer_cost_10gbe() {
        // 100 MB over 10 Gbps ≈ 80 ms
        let ms = transfer_cost_ms(100 * 1024 * 1024, 10.0);
        assert!(ms > 50.0 && ms < 120.0, "got {ms}");
    }

    #[test]
    fn profitability_large_compute_small_transfer() {
        // Large compute (1M units), small transfer (1 KB), fast link
        assert!(is_distribution_profitable(
            1_000_000, 1024, 80.0, 1000.0 // 1000 units/ms local throughput
        ));
    }

    #[test]
    fn profitability_small_compute_large_transfer() {
        // Small compute (100 units), large transfer (100 MB), slow link
        assert!(!is_distribution_profitable(
            100,
            100 * 1024 * 1024,
            10.0,
            1000.0
        ));
    }
}
