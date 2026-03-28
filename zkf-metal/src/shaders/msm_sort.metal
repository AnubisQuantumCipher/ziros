// ============================================================================
// MSM Sparse Matrix Transposition — Sorted Bucket Accumulation
// Replaces O(n * total_buckets) scan with O(n) sort + O(n) accumulation.
//
// Depends on Fp, G1Proj, g1_identity, g1_add_mixed, fp_sub, fp_zero
// from msm_bn254.metal (concatenated before this file at build time).
// ============================================================================

// --- Standard (unsigned) path ---

// Phase 2a: Count points per bucket (atomic increment)
// Each thread processes one point across all windows.
kernel void msm_sort_count(
    device const uint32_t *point_bucket_map [[buffer(0)]],
    device atomic_uint *bucket_counts [[buffer(1)]],
    constant uint32_t &n_points [[buffer(2)]],
    constant uint32_t &num_buckets [[buffer(3)]],
    constant uint32_t &num_windows [[buffer(4)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_points) return;
    for (uint32_t w = 0; w < num_windows; w++) {
        uint32_t bucket = point_bucket_map[tid * num_windows + w];
        uint32_t global_idx = w * num_buckets + bucket;
        atomic_fetch_add_explicit(&bucket_counts[global_idx], 1u, memory_order_relaxed);
    }
}

// Phase 2c: Scatter point indices into sorted order (atomic write cursor)
// Each thread writes its point index into the sorted position for each window.
kernel void msm_sort_scatter(
    device const uint32_t *point_bucket_map [[buffer(0)]],
    device const uint32_t *bucket_offsets [[buffer(1)]],
    device atomic_uint *write_cursors [[buffer(2)]],
    device uint32_t *sorted_indices [[buffer(3)]],
    constant uint32_t &n_points [[buffer(4)]],
    constant uint32_t &num_buckets [[buffer(5)]],
    constant uint32_t &num_windows [[buffer(6)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_points) return;
    for (uint32_t w = 0; w < num_windows; w++) {
        uint32_t bucket = point_bucket_map[tid * num_windows + w];
        uint32_t global_idx = w * num_buckets + bucket;
        uint32_t pos = bucket_offsets[global_idx] +
            atomic_fetch_add_explicit(&write_cursors[global_idx], 1u, memory_order_relaxed);
        sorted_indices[pos] = tid;
    }
}

// Phase 2d: Sorted bucket accumulation — each bucket reads ONLY its assigned points.
// Complexity: O(points_in_bucket) per thread instead of O(n_points).
kernel void msm_bucket_acc_sorted(
    device const uint64_t *bases_x [[buffer(0)]],
    device const uint64_t *bases_y [[buffer(1)]],
    device const uint32_t *sorted_indices [[buffer(2)]],
    device const uint32_t *bucket_offsets [[buffer(3)]],
    device const uint32_t *bucket_counts [[buffer(4)]],
    device uint64_t *bucket_results [[buffer(5)]],
    constant uint32_t &num_buckets [[buffer(6)]],
    constant uint32_t &num_windows [[buffer(7)]],
    uint tid [[thread_position_in_grid]])
{
    uint32_t total_buckets = num_windows * num_buckets;
    if (tid >= total_buckets) return;

    uint32_t bucket = tid % num_buckets;

    // Bucket 0 = identity (zero scalar window)
    if (bucket == 0) {
        uint32_t out = tid * 12;
        for (int i = 0; i < 12; i++) bucket_results[out + i] = 0;
        return;
    }

    uint32_t count = bucket_counts[tid];
    uint32_t offset = bucket_offsets[tid];

    G1Proj acc = g1_identity();

    for (uint32_t i = 0; i < count; i++) {
        uint32_t pt_idx = sorted_indices[offset + i];
        Fp px, py;
        for (int j = 0; j < 4; j++) {
            px.limbs[j] = bases_x[pt_idx * 4 + j];
            py.limbs[j] = bases_y[pt_idx * 4 + j];
        }
        acc = g1_add_mixed(acc, px, py);
    }

    uint32_t out = tid * 12;
    for (int j = 0; j < 4; j++) {
        bucket_results[out + j]     = acc.x.limbs[j];
        bucket_results[out + 4 + j] = acc.y.limbs[j];
        bucket_results[out + 8 + j] = acc.z.limbs[j];
    }
}

// --- NAF (signed-digit) path ---

// Count: extract abs_bucket from NAF encoding (entry = abs_bucket | sign << 31)
kernel void msm_sort_count_naf(
    device const uint32_t *naf_map [[buffer(0)]],
    device atomic_uint *bucket_counts [[buffer(1)]],
    constant uint32_t &n_points [[buffer(2)]],
    constant uint32_t &num_buckets_naf [[buffer(3)]],
    constant uint32_t &num_windows [[buffer(4)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_points) return;
    for (uint32_t w = 0; w < num_windows; w++) {
        uint32_t entry = naf_map[tid * num_windows + w];
        uint32_t abs_bucket = entry & 0x7FFFFFFFu;
        uint32_t global_idx = w * num_buckets_naf + abs_bucket;
        atomic_fetch_add_explicit(&bucket_counts[global_idx], 1u, memory_order_relaxed);
    }
}

// Scatter for NAF: pack (point_index | sign << 31) into sorted array.
// Sign bit is preserved from the original NAF map entry so the accumulation
// kernel can negate Y when sign=1 without a second buffer lookup.
kernel void msm_sort_scatter_naf(
    device const uint32_t *naf_map [[buffer(0)]],
    device const uint32_t *bucket_offsets [[buffer(1)]],
    device atomic_uint *write_cursors [[buffer(2)]],
    device uint32_t *sorted_indices [[buffer(3)]],
    constant uint32_t &n_points [[buffer(4)]],
    constant uint32_t &num_buckets_naf [[buffer(5)]],
    constant uint32_t &num_windows [[buffer(6)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_points) return;
    for (uint32_t w = 0; w < num_windows; w++) {
        uint32_t entry = naf_map[tid * num_windows + w];
        uint32_t abs_bucket = entry & 0x7FFFFFFFu;
        uint32_t sign = entry & 0x80000000u;
        uint32_t global_idx = w * num_buckets_naf + abs_bucket;
        uint32_t pos = bucket_offsets[global_idx] +
            atomic_fetch_add_explicit(&write_cursors[global_idx], 1u, memory_order_relaxed);
        sorted_indices[pos] = tid | sign;
    }
}

// Sorted NAF accumulation: reads packed (point_index | sign) entries.
// Negates Y coordinate when sign bit is set (NAF negative digit).
kernel void msm_bucket_acc_sorted_naf(
    device const uint64_t *bases_x [[buffer(0)]],
    device const uint64_t *bases_y [[buffer(1)]],
    device const uint32_t *sorted_indices [[buffer(2)]],
    device const uint32_t *bucket_offsets [[buffer(3)]],
    device const uint32_t *bucket_counts [[buffer(4)]],
    device uint64_t *bucket_results [[buffer(5)]],
    constant uint32_t &num_buckets_naf [[buffer(6)]],
    constant uint32_t &num_windows [[buffer(7)]],
    uint tid [[thread_position_in_grid]])
{
    uint32_t total_buckets = num_windows * num_buckets_naf;
    if (tid >= total_buckets) return;

    uint32_t bucket = tid % num_buckets_naf;

    if (bucket == 0) {
        uint32_t out = tid * 12;
        for (int i = 0; i < 12; i++) bucket_results[out + i] = 0;
        return;
    }

    uint32_t count = bucket_counts[tid];
    uint32_t offset = bucket_offsets[tid];

    G1Proj acc = g1_identity();

    for (uint32_t i = 0; i < count; i++) {
        uint32_t packed = sorted_indices[offset + i];
        uint32_t pt_idx = packed & 0x7FFFFFFFu;
        uint32_t sign = packed >> 31;

        Fp px, py;
        for (int j = 0; j < 4; j++) {
            px.limbs[j] = bases_x[pt_idx * 4 + j];
            py.limbs[j] = bases_y[pt_idx * 4 + j];
        }

        // Negate Y if sign bit is set: -P = (X, -Y) on BN254
        if (sign) {
            py = fp_sub(fp_zero(), py);
        }

        acc = g1_add_mixed(acc, px, py);
    }

    uint32_t out = tid * 12;
    for (int j = 0; j < 4; j++) {
        bucket_results[out + j]     = acc.x.limbs[j];
        bucket_results[out + 4 + j] = acc.y.limbs[j];
        bucket_results[out + 8 + j] = acc.z.limbs[j];
    }
}
