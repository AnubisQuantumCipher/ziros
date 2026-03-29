// FRI folding kernels for Goldilocks and BabyBear fields.
// Uses gl_add, gl_sub, gl_mul from field_goldilocks.metal
// Uses bb_add, bb_sub, bb_mul from field_babybear.metal
// (all concatenated at compile time — do NOT redefine field helpers here)

// inv(2) in Goldilocks = (p+1)/2
constant uint64_t GL_INV_TWO = 0x7FFFFFFF80000001ULL;

// inv(2) in BabyBear = (p+1)/2 = 1006632961
constant uint32_t BB_INV_TWO = 1006632961u;

// --- FRI fold (Goldilocks) ---
// g[i] = (f[2i] + f[2i+1]) / 2 + alpha * (f[2i] - f[2i+1]) * inv_twiddles[i]
kernel void fri_fold_goldilocks(
    device const uint64_t* evals [[buffer(0)]],
    device uint64_t* output [[buffer(1)]],
    constant uint64_t& alpha [[buffer(2)]],
    device const uint64_t* inv_twiddles [[buffer(3)]],
    constant uint32_t& n_output [[buffer(4)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_output) return;

    uint64_t f_even = evals[2 * tid];
    uint64_t f_odd = evals[2 * tid + 1];

    uint64_t sum = gl_mul(gl_add(f_even, f_odd), GL_INV_TWO);
    uint64_t diff = gl_mul(gl_sub(f_even, f_odd), inv_twiddles[tid]);
    diff = gl_mul(diff, alpha);

    output[tid] = gl_add(sum, diff);
}

// --- FRI fold (BabyBear) ---
kernel void fri_fold_babybear(
    device const uint32_t* evals [[buffer(0)]],
    device uint32_t* output [[buffer(1)]],
    constant uint32_t& alpha [[buffer(2)]],
    device const uint32_t* inv_twiddles [[buffer(3)]],
    constant uint32_t& n_output [[buffer(4)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_output) return;

    uint32_t f_even = evals[2 * tid];
    uint32_t f_odd = evals[2 * tid + 1];

    uint32_t sum = bb_mul(bb_add(f_even, f_odd), BB_INV_TWO);
    uint32_t diff = bb_mul(bb_sub(f_even, f_odd), inv_twiddles[tid]);
    diff = bb_mul(diff, alpha);

    output[tid] = bb_add(sum, diff);
}
