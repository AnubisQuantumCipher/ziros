// ============================================================================
// MSM Phase 3+4: GPU bucket reduction and window combination
// Eliminates ~52MB CPU readback by doing final reduction on GPU.
//
// Reuses Fp, G1Proj, fp_add, fp_sub, fp_mul, g1_add, g1_is_identity, g1_identity
// from msm_bn254.metal (concatenated before this file at compile time).
// ============================================================================

/// Bucket reduction: running-sum accumulation within each window.
/// One thread per window. All windows run in parallel.
/// Input: bucket_data[num_windows * num_buckets * 12] (G1Proj as 12 u64s)
/// Output: window_results[num_windows * 12]
kernel void msm_bucket_reduce(
    device const uint64_t* bucket_data [[buffer(0)]],
    device uint64_t* window_results [[buffer(1)]],
    constant uint32_t& num_buckets [[buffer(2)]],
    constant uint32_t& num_windows [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= num_windows) return;

    uint window = tid;
    uint base_offset = window * uint(num_buckets) * 12;

    G1Proj running_sum = g1_identity();
    G1Proj result = g1_identity();

    // Running sum from highest bucket down
    for (int b = int(num_buckets) - 1; b >= 1; b--) {
        uint offset = base_offset + uint(b) * 12;
        G1Proj bucket;
        bucket.x.limbs[0] = bucket_data[offset + 0];
        bucket.x.limbs[1] = bucket_data[offset + 1];
        bucket.x.limbs[2] = bucket_data[offset + 2];
        bucket.x.limbs[3] = bucket_data[offset + 3];
        bucket.y.limbs[0] = bucket_data[offset + 4];
        bucket.y.limbs[1] = bucket_data[offset + 5];
        bucket.y.limbs[2] = bucket_data[offset + 6];
        bucket.y.limbs[3] = bucket_data[offset + 7];
        bucket.z.limbs[0] = bucket_data[offset + 8];
        bucket.z.limbs[1] = bucket_data[offset + 9];
        bucket.z.limbs[2] = bucket_data[offset + 10];
        bucket.z.limbs[3] = bucket_data[offset + 11];

        running_sum = g1_add_proj(running_sum, bucket);
        result = g1_add_proj(result, running_sum);
    }

    // Write window result
    uint out_offset = window * 12;
    window_results[out_offset + 0] = result.x.limbs[0];
    window_results[out_offset + 1] = result.x.limbs[1];
    window_results[out_offset + 2] = result.x.limbs[2];
    window_results[out_offset + 3] = result.x.limbs[3];
    window_results[out_offset + 4] = result.y.limbs[0];
    window_results[out_offset + 5] = result.y.limbs[1];
    window_results[out_offset + 6] = result.y.limbs[2];
    window_results[out_offset + 7] = result.y.limbs[3];
    window_results[out_offset + 8] = result.z.limbs[0];
    window_results[out_offset + 9] = result.z.limbs[1];
    window_results[out_offset + 10] = result.z.limbs[2];
    window_results[out_offset + 11] = result.z.limbs[3];
}

/// Window combination: Horner's method across windows.
/// Single thread. Double c times, add next window.
/// Input: window_results[num_windows * 12]
/// Output: final_result[12] (one G1Projective)
kernel void msm_window_combine(
    device const uint64_t* window_results [[buffer(0)]],
    device uint64_t* final_result [[buffer(1)]],
    constant uint32_t& num_windows [[buffer(2)]],
    constant uint32_t& window_bits [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid != 0) return;

    // Start from highest window
    uint last_w = num_windows - 1;
    uint offset = last_w * 12;
    G1Proj result;
    result.x.limbs[0] = window_results[offset + 0];
    result.x.limbs[1] = window_results[offset + 1];
    result.x.limbs[2] = window_results[offset + 2];
    result.x.limbs[3] = window_results[offset + 3];
    result.y.limbs[0] = window_results[offset + 4];
    result.y.limbs[1] = window_results[offset + 5];
    result.y.limbs[2] = window_results[offset + 6];
    result.y.limbs[3] = window_results[offset + 7];
    result.z.limbs[0] = window_results[offset + 8];
    result.z.limbs[1] = window_results[offset + 9];
    result.z.limbs[2] = window_results[offset + 10];
    result.z.limbs[3] = window_results[offset + 11];

    // Horner: for each lower window, double c times then add
    for (int w = int(last_w) - 1; w >= 0; w--) {
        for (uint d = 0; d < window_bits; d++) {
            result = g1_add_proj(result, result);  // point doubling
        }

        uint w_offset = uint(w) * 12;
        G1Proj win;
        win.x.limbs[0] = window_results[w_offset + 0];
        win.x.limbs[1] = window_results[w_offset + 1];
        win.x.limbs[2] = window_results[w_offset + 2];
        win.x.limbs[3] = window_results[w_offset + 3];
        win.y.limbs[0] = window_results[w_offset + 4];
        win.y.limbs[1] = window_results[w_offset + 5];
        win.y.limbs[2] = window_results[w_offset + 6];
        win.y.limbs[3] = window_results[w_offset + 7];
        win.z.limbs[0] = window_results[w_offset + 8];
        win.z.limbs[1] = window_results[w_offset + 9];
        win.z.limbs[2] = window_results[w_offset + 10];
        win.z.limbs[3] = window_results[w_offset + 11];

        result = g1_add_proj(result, win);
    }

    // Write final result
    final_result[0] = result.x.limbs[0];
    final_result[1] = result.x.limbs[1];
    final_result[2] = result.x.limbs[2];
    final_result[3] = result.x.limbs[3];
    final_result[4] = result.y.limbs[0];
    final_result[5] = result.y.limbs[1];
    final_result[6] = result.y.limbs[2];
    final_result[7] = result.y.limbs[3];
    final_result[8] = result.z.limbs[0];
    final_result[9] = result.z.limbs[1];
    final_result[10] = result.z.limbs[2];
    final_result[11] = result.z.limbs[3];
}
