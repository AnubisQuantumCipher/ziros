// Batch field arithmetic kernels for GPU-accelerated witness generation.
// Field arithmetic helpers are included before this file via concatenation.

// ============================================================
// Goldilocks batch operations
// ============================================================

kernel void batch_add_goldilocks(
    device uint64_t *a [[buffer(0)]],
    device const uint64_t *b [[buffer(1)]],
    constant uint32_t &count [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= count) return;
    a[tid] = gl_add(a[tid], b[tid]);
}

kernel void batch_sub_goldilocks(
    device uint64_t *a [[buffer(0)]],
    device const uint64_t *b [[buffer(1)]],
    constant uint32_t &count [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= count) return;
    a[tid] = gl_sub(a[tid], b[tid]);
}

kernel void batch_mul_goldilocks(
    device uint64_t *a [[buffer(0)]],
    device const uint64_t *b [[buffer(1)]],
    constant uint32_t &count [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= count) return;
    a[tid] = gl_mul(a[tid], b[tid]);
}

// Batch inversion using Montgomery's trick (parallelized prefix products).
// Phase 1: Compute prefix products.
// Phase 2: Invert the total product (single element).
// Phase 3: Back-propagate to get individual inverses.
// This is dispatched from Rust in 3 kernel calls with barriers.

// Phase 1: prefix product (serial per chunk, parallel across chunks)
kernel void batch_inv_prefix_goldilocks(
    device const uint64_t *input [[buffer(0)]],
    device uint64_t *prefix [[buffer(1)]],
    constant uint32_t &count [[buffer(2)]],
    constant uint32_t &chunk_size [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    uint32_t start = tid * chunk_size;
    if (start >= count) return;
    uint32_t end = min(start + chunk_size, count);

    uint64_t acc = 1;
    for (uint32_t i = start; i < end; i++) {
        acc = gl_mul(acc, input[i]);
        prefix[i] = acc;
    }
}

// Phase 3: back-propagate inverses
kernel void batch_inv_backprop_goldilocks(
    device const uint64_t *input [[buffer(0)]],
    device uint64_t *prefix [[buffer(1)]],
    device uint64_t *output [[buffer(2)]],
    constant uint32_t &count [[buffer(3)]],
    constant uint32_t &chunk_size [[buffer(4)]],
    uint tid [[thread_position_in_grid]])
{
    uint32_t start = tid * chunk_size;
    if (start >= count) return;
    uint32_t end = min(start + chunk_size, count);

    // Get the inverse of the total prefix product for this chunk
    uint64_t inv_acc = prefix[end - 1]; // already inverted by CPU between phases

    for (uint32_t i = end; i > start; i--) {
        uint32_t idx = i - 1;
        if (idx > start) {
            output[idx] = gl_mul(inv_acc, prefix[idx - 1]);
        } else {
            output[idx] = inv_acc;
        }
        inv_acc = gl_mul(inv_acc, input[idx]);
    }
}

// ============================================================
// BabyBear batch operations
// ============================================================

kernel void batch_add_babybear(
    device uint32_t *a [[buffer(0)]],
    device const uint32_t *b [[buffer(1)]],
    constant uint32_t &count [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= count) return;
    a[tid] = bb_add(a[tid], b[tid]);
}

kernel void batch_sub_babybear(
    device uint32_t *a [[buffer(0)]],
    device const uint32_t *b [[buffer(1)]],
    constant uint32_t &count [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= count) return;
    a[tid] = bb_sub(a[tid], b[tid]);
}

kernel void batch_mul_babybear(
    device uint32_t *a [[buffer(0)]],
    device const uint32_t *b [[buffer(1)]],
    constant uint32_t &count [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= count) return;
    a[tid] = bb_mul(a[tid], b[tid]);
}
