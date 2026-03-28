// Polynomial operations on Goldilocks and BabyBear fields.
// Uses gl_add, gl_sub, gl_mul from field_goldilocks.metal
// Uses bb_add, bb_sub, bb_mul from field_babybear.metal
// (all concatenated at compile time — do NOT redefine field helpers here)

// --- Goldilocks power helper (needed for coset shift) ---
static inline uint64_t gl_pow_poly(uint64_t base, uint64_t exp) {
    uint64_t result = 1;
    while (exp > 0) {
        if (exp & 1) result = gl_mul(result, base);
        exp >>= 1;
        base = gl_mul(base, base);
    }
    return result;
}

static inline uint64_t gl_inv_poly(uint64_t value) {
    if (value == 0) return 0;
    return gl_pow_poly(value, GL_P - 2);
}

// --- Goldilocks polynomial evaluation (Horner's method) ---
kernel void poly_eval_goldilocks(
    device const uint64_t* coeffs [[buffer(0)]],
    device const uint64_t* points [[buffer(1)]],
    device uint64_t* output [[buffer(2)]],
    constant uint32_t& degree [[buffer(3)]],
    constant uint32_t& n_points [[buffer(4)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_points) return;

    uint64_t x = points[tid];
    uint64_t result = 0;

    for (int i = int(degree) - 1; i >= 0; i--) {
        result = gl_add(gl_mul(result, x), coeffs[i]);
    }

    output[tid] = result;
}

// --- Batch polynomial evaluation ---
kernel void poly_batch_eval_goldilocks(
    device const uint64_t* coeffs_flat [[buffer(0)]],
    device const uint64_t* points [[buffer(1)]],
    device uint64_t* output [[buffer(2)]],
    constant uint32_t& degree [[buffer(3)]],
    constant uint32_t& n_points [[buffer(4)]],
    constant uint32_t& n_polys [[buffer(5)]],
    uint2 tid [[thread_position_in_grid]])
{
    uint point_idx = tid.x;
    uint poly_idx = tid.y;
    if (point_idx >= n_points || poly_idx >= n_polys) return;

    uint64_t x = points[point_idx];
    device const uint64_t* coeffs = coeffs_flat + poly_idx * degree;
    uint64_t result = 0;

    for (int i = int(degree) - 1; i >= 0; i--) {
        result = gl_add(gl_mul(result, x), coeffs[i]);
    }

    output[poly_idx * n_points + point_idx] = result;
}

// --- Quotient polynomial ---
kernel void poly_quotient_goldilocks(
    device const uint64_t* evals [[buffer(0)]],
    device uint64_t* output [[buffer(1)]],
    constant uint64_t& z [[buffer(2)]],
    constant uint64_t& f_z [[buffer(3)]],
    constant uint64_t& generator [[buffer(4)]],
    constant uint32_t& n [[buffer(5)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    uint64_t x = gl_pow_poly(generator, uint64_t(tid));
    uint64_t numerator = gl_sub(evals[tid], f_z);
    uint64_t denominator = gl_sub(x, z);
    output[tid] = (denominator == 0) ? 0 : gl_mul(numerator, gl_inv_poly(denominator));
}

// --- Coset shift: multiply coeffs by shift^i ---
kernel void poly_coset_shift_goldilocks(
    device uint64_t* coeffs [[buffer(0)]],
    constant uint64_t& shift [[buffer(1)]],
    constant uint32_t& n [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;
    uint64_t shift_power = gl_pow_poly(shift, uint64_t(tid));
    coeffs[tid] = gl_mul(coeffs[tid], shift_power);
}

// --- BabyBear polynomial evaluation ---
kernel void poly_eval_babybear(
    device const uint32_t* coeffs [[buffer(0)]],
    device const uint32_t* points [[buffer(1)]],
    device uint32_t* output [[buffer(2)]],
    constant uint32_t& degree [[buffer(3)]],
    constant uint32_t& n_points [[buffer(4)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_points) return;

    uint32_t x = points[tid];
    uint32_t result = 0;

    for (int i = int(degree) - 1; i >= 0; i--) {
        result = bb_add(bb_mul(result, x), coeffs[i]);
    }

    output[tid] = result;
}
