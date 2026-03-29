// Batch Poseidon2 permutation for Goldilocks field (width=16)
// Bit-identical with p3-goldilocks Poseidon2Goldilocks<16>
//
// Field arithmetic helpers (gl_add, gl_sub, gl_mul) included via concatenation.
//
// Algorithm (from p3-poseidon2):
//   Initial: external_MDS(state)
//   First half external rounds: for each round: RC+sbox → external_MDS
//   Internal rounds: for each round: RC+sbox on state[0] → internal_matmul
//   Second half external rounds: for each round: RC+sbox → external_MDS
//
// External MDS (width=16): apply M4 to each 4-element chunk, then add cross-chunk sums
// M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
// Internal linear layer: state[i] = diag[i]*state[i] + sum(state)

// S-box: x^7 for Goldilocks
static inline uint64_t p2_sbox(uint64_t x) {
    uint64_t x2 = gl_mul(x, x);
    uint64_t x3 = gl_mul(x2, x);
    uint64_t x4 = gl_mul(x2, x2);
    return gl_mul(x4, x3);
}

// M4 multiplication: [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
// Uses the optimized formula from p3 (7 adds, 2 doubles)
static inline void apply_mat4(thread uint64_t &x0, thread uint64_t &x1,
                              thread uint64_t &x2, thread uint64_t &x3) {
    uint64_t t01 = gl_add(x0, x1);
    uint64_t t23 = gl_add(x2, x3);
    uint64_t t0123 = gl_add(t01, t23);
    uint64_t t01123 = gl_add(t0123, x1);
    uint64_t t01233 = gl_add(t0123, x3);
    // Need to compute before overwriting
    uint64_t new_x3 = gl_add(t01233, gl_add(x0, x0)); // 3*x0 + x1 + x2 + 2*x3
    uint64_t new_x1 = gl_add(t01123, gl_add(x2, x2)); // x0 + 2*x1 + 3*x2 + x3
    uint64_t new_x0 = gl_add(t01123, t01);             // 2*x0 + 3*x1 + x2 + x3
    uint64_t new_x2 = gl_add(t01233, t23);             // x0 + x1 + 2*x2 + 3*x3
    x0 = new_x0;
    x1 = new_x1;
    x2 = new_x2;
    x3 = new_x3;
}

// External MDS for width=16:
// 1. Apply M4 to each consecutive group of 4 elements
// 2. Compute sums[k] = sum of state[j+k] for j in {0,4,8,12}, k in {0,1,2,3}
// 3. state[i] += sums[i % 4]
static inline void external_mds(thread uint64_t *state) {
    // Apply M4 to each quarter
    apply_mat4(state[0], state[1], state[2], state[3]);
    apply_mat4(state[4], state[5], state[6], state[7]);
    apply_mat4(state[8], state[9], state[10], state[11]);
    apply_mat4(state[12], state[13], state[14], state[15]);

    // Compute cross-chunk sums
    uint64_t sums[4];
    for (int k = 0; k < 4; k++) {
        sums[k] = gl_add(gl_add(state[k], state[4 + k]),
                         gl_add(state[8 + k], state[12 + k]));
    }

    // Add sums
    for (int i = 0; i < 16; i++) {
        state[i] = gl_add(state[i], sums[i % 4]);
    }
}

// Internal linear layer: state[i] = diag[i]*state[i] + sum(all state)
static inline void internal_matmul(thread uint64_t *state,
                                   device const uint64_t *diag) {
    // Compute sum of all elements
    uint64_t sum = 0;
    for (int i = 0; i < 16; i++) {
        sum = gl_add(sum, state[i]);
    }
    // state[i] = diag[i] * state[i] + sum
    for (int i = 0; i < 16; i++) {
        state[i] = gl_add(gl_mul(state[i], diag[i]), sum);
    }
}

// Main Poseidon2 batch kernel
// Each thread computes one full Poseidon2 permutation (width=16)
//
// Buffer layout:
//   buffer(0): states — n_perms * 16 uint64_t values
//   buffer(1): round_constants — [initial_ext (half_f * 16)] [internal (rounds_p)] [terminal_ext (half_f * 16)]
//   buffer(2): n_perms
//   buffer(3): n_external_rounds (total = rounds_f)
//   buffer(4): n_internal_rounds (= rounds_p)
//   buffer(5): internal_diag — 16 uint64_t diagonal matrix entries (MATRIX_DIAG_16_GOLDILOCKS)
kernel void poseidon2_goldilocks(
    device uint64_t *states [[buffer(0)]],
    device const uint64_t *round_constants [[buffer(1)]],
    constant uint32_t &n_perms [[buffer(2)]],
    constant uint32_t &n_external_rounds [[buffer(3)]],
    constant uint32_t &n_internal_rounds [[buffer(4)]],
    device const uint64_t *internal_diag [[buffer(5)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_perms) return;

    // Load state into registers
    uint64_t state[16];
    uint32_t offset = tid * 16;
    for (int i = 0; i < 16; i++) {
        state[i] = states[offset + i];
    }

    uint32_t rc_idx = 0;
    uint32_t half_ext = n_external_rounds / 2;

    // ---- Initial external MDS (before any rounds) ----
    external_mds(state);

    // ---- First half external rounds ----
    for (uint32_t r = 0; r < half_ext; r++) {
        // Add round constants + S-box on all elements
        for (int i = 0; i < 16; i++) {
            state[i] = gl_add(state[i], round_constants[rc_idx + i]);
            state[i] = p2_sbox(state[i]);
        }
        rc_idx += 16;
        // External MDS
        external_mds(state);
    }

    // ---- Internal rounds ----
    for (uint32_t r = 0; r < n_internal_rounds; r++) {
        // Add round constant + S-box on state[0] only
        state[0] = gl_add(state[0], round_constants[rc_idx]);
        state[0] = p2_sbox(state[0]);
        rc_idx += 1;
        // Internal linear layer
        internal_matmul(state, internal_diag);
    }

    // ---- Second half external rounds ----
    for (uint32_t r = 0; r < half_ext; r++) {
        // Add round constants + S-box on all elements
        for (int i = 0; i < 16; i++) {
            state[i] = gl_add(state[i], round_constants[rc_idx + i]);
            state[i] = p2_sbox(state[i]);
        }
        rc_idx += 16;
        // External MDS
        external_mds(state);
    }

    // Write back
    for (int i = 0; i < 16; i++) {
        states[offset + i] = state[i];
    }
}

// ============================================================================
// BabyBear Poseidon2 permutation (width=16, S-box: x^7, 32-bit field)
// Field arithmetic helpers (bb_add, bb_sub, bb_mul) included via concatenation.
// ============================================================================

// S-box: x^7 for BabyBear
static inline uint32_t bb_p2_sbox(uint32_t x) {
    uint32_t x2 = bb_mul(x, x);
    uint32_t x3 = bb_mul(x2, x);
    uint32_t x4 = bb_mul(x2, x2);
    return bb_mul(x4, x3);
}

// M4 circulant [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] over BabyBear
static inline void bb_apply_mat4(thread uint32_t &x0, thread uint32_t &x1,
                                 thread uint32_t &x2, thread uint32_t &x3) {
    uint32_t t01 = bb_add(x0, x1);
    uint32_t t23 = bb_add(x2, x3);
    uint32_t t0123 = bb_add(t01, t23);
    uint32_t t01123 = bb_add(t0123, x1);
    uint32_t t01233 = bb_add(t0123, x3);
    uint32_t new_x3 = bb_add(t01233, bb_add(x0, x0));
    uint32_t new_x1 = bb_add(t01123, bb_add(x2, x2));
    uint32_t new_x0 = bb_add(t01123, t01);
    uint32_t new_x2 = bb_add(t01233, t23);
    x0 = new_x0;
    x1 = new_x1;
    x2 = new_x2;
    x3 = new_x3;
}

static inline void bb_external_mds(thread uint32_t *state) {
    bb_apply_mat4(state[0], state[1], state[2], state[3]);
    bb_apply_mat4(state[4], state[5], state[6], state[7]);
    bb_apply_mat4(state[8], state[9], state[10], state[11]);
    bb_apply_mat4(state[12], state[13], state[14], state[15]);

    uint32_t sums[4];
    for (int k = 0; k < 4; k++) {
        sums[k] = bb_add(bb_add(state[k], state[4 + k]),
                         bb_add(state[8 + k], state[12 + k]));
    }
    for (int i = 0; i < 16; i++) {
        state[i] = bb_add(state[i], sums[i % 4]);
    }
}

static inline void bb_internal_matmul(thread uint32_t *state,
                                      device const uint32_t *diag) {
    uint32_t sum = 0;
    for (int i = 0; i < 16; i++) {
        sum = bb_add(sum, state[i]);
    }
    for (int i = 0; i < 16; i++) {
        state[i] = bb_add(bb_mul(state[i], diag[i]), sum);
    }
}

kernel void poseidon2_babybear(
    device uint32_t *states [[buffer(0)]],
    device const uint32_t *round_constants [[buffer(1)]],
    constant uint32_t &n_perms [[buffer(2)]],
    constant uint32_t &n_external_rounds [[buffer(3)]],
    constant uint32_t &n_internal_rounds [[buffer(4)]],
    device const uint32_t *internal_diag [[buffer(5)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_perms) return;

    uint32_t state[16];
    uint32_t offset = tid * 16;
    for (int i = 0; i < 16; i++) {
        state[i] = states[offset + i];
    }

    uint32_t rc_idx = 0;
    uint32_t half_ext = n_external_rounds / 2;

    bb_external_mds(state);

    for (uint32_t r = 0; r < half_ext; r++) {
        for (int i = 0; i < 16; i++) {
            state[i] = bb_add(state[i], round_constants[rc_idx + i]);
            state[i] = bb_p2_sbox(state[i]);
        }
        rc_idx += 16;
        bb_external_mds(state);
    }

    for (uint32_t r = 0; r < n_internal_rounds; r++) {
        state[0] = bb_add(state[0], round_constants[rc_idx]);
        state[0] = bb_p2_sbox(state[0]);
        rc_idx += 1;
        bb_internal_matmul(state, internal_diag);
    }

    for (uint32_t r = 0; r < half_ext; r++) {
        for (int i = 0; i < 16; i++) {
            state[i] = bb_add(state[i], round_constants[rc_idx + i]);
            state[i] = bb_p2_sbox(state[i]);
        }
        rc_idx += 16;
        bb_external_mds(state);
    }

    for (int i = 0; i < 16; i++) {
        states[offset + i] = state[i];
    }
}

// ============================================================================
// SIMD-cooperative Poseidon2 BabyBear kernel (width=16)
//
// Uses 16 threads per permutation within a simdgroup. Each thread holds one
// state element. The internal layer sum uses simd shuffle tree reduction.
// This reduces register pressure and exploits M4 Max's 32-wide simdgroups.
// ============================================================================

kernel void poseidon2_babybear_simd(
    device uint32_t *states [[buffer(0)]],
    device const uint32_t *round_constants [[buffer(1)]],
    constant uint32_t &n_perms [[buffer(2)]],
    constant uint32_t &n_external_rounds [[buffer(3)]],
    constant uint32_t &n_internal_rounds [[buffer(4)]],
    device const uint32_t *internal_diag [[buffer(5)]],
    uint tid [[thread_position_in_grid]],
    ushort simd_lane [[thread_index_in_simdgroup]])
{
    // 16 threads cooperate on one permutation
    uint32_t perm_id = tid / 16;
    ushort elem_id = tid % 16;

    if (perm_id >= n_perms) return;

    // Load my element
    uint32_t s = states[perm_id * 16 + elem_id];

    uint32_t rc_idx = 0;
    uint32_t half_ext = n_external_rounds / 2;

    // Load diagonal entry for this element
    uint32_t my_diag = internal_diag[elem_id];

    // ---- Helper: SIMD external MDS ----
    // M4 on groups of 4 via simd_shuffle, then cross-group sums
    // We use simd_shuffle with the actual simd_lane, mapping elem_id to simd_lane offset
    // Since tid%16 maps to lanes within the simdgroup (or across if simdgroup > 16),
    // we use quad shuffles for M4 and explicit shuffles for cross-group sums.

    // Compute base simd lane for this permutation's group of 16
    ushort perm_base = (ushort)((tid / 16) * 16) % 32; // position within simdgroup

    #define SIMD_EXT_MDS() do { \
        /* M4 within each group of 4 */ \
        ushort g_base = perm_base + (elem_id / 4) * 4; \
        uint32_t x0 = simd_shuffle(s, g_base + 0); \
        uint32_t x1 = simd_shuffle(s, g_base + 1); \
        uint32_t x2 = simd_shuffle(s, g_base + 2); \
        uint32_t x3 = simd_shuffle(s, g_base + 3); \
        uint32_t t01 = bb_add(x0, x1); \
        uint32_t t23 = bb_add(x2, x3); \
        uint32_t t0123 = bb_add(t01, t23); \
        uint32_t t01123 = bb_add(t0123, x1); \
        uint32_t t01233 = bb_add(t0123, x3); \
        ushort pig = elem_id % 4; \
        if (pig == 0) s = bb_add(t01123, t01); \
        else if (pig == 1) s = bb_add(t01123, bb_add(x2, x2)); \
        else if (pig == 2) s = bb_add(t01233, t23); \
        else s = bb_add(t01233, bb_add(x0, x0)); \
        /* Cross-group sums */ \
        ushort k = elem_id % 4; \
        uint32_t cs = bb_add( \
            bb_add(simd_shuffle(s, perm_base + k), simd_shuffle(s, perm_base + 4 + k)), \
            bb_add(simd_shuffle(s, perm_base + 8 + k), simd_shuffle(s, perm_base + 12 + k))); \
        s = bb_add(s, cs); \
    } while(0)

    // ---- Initial external MDS ----
    SIMD_EXT_MDS();

    // ---- First half external rounds ----
    for (uint32_t r = 0; r < half_ext; r++) {
        s = bb_add(s, round_constants[rc_idx + elem_id]);
        s = bb_p2_sbox(s);
        rc_idx += 16;
        SIMD_EXT_MDS();
    }

    // ---- Internal rounds ----
    for (uint32_t r = 0; r < n_internal_rounds; r++) {
        // RC + S-box on element 0 only
        if (elem_id == 0) {
            s = bb_add(s, round_constants[rc_idx]);
            s = bb_p2_sbox(s);
        }
        rc_idx += 1;

        // Internal matmul: state[i] = diag[i]*state[i] + sum(all 16 elements)
        // Tree reduction across 16 lanes using simd_shuffle
        uint32_t partial = s;
        partial = bb_add(partial, simd_shuffle_xor(partial, 1));
        partial = bb_add(partial, simd_shuffle_xor(partial, 2));
        partial = bb_add(partial, simd_shuffle_xor(partial, 4));
        partial = bb_add(partial, simd_shuffle_xor(partial, 8));
        // Broadcast sum from lane 0 of this perm's group
        uint32_t sum_all = simd_shuffle(partial, perm_base);

        s = bb_add(bb_mul(s, my_diag), sum_all);
    }

    // ---- Second half external rounds ----
    for (uint32_t r = 0; r < half_ext; r++) {
        s = bb_add(s, round_constants[rc_idx + elem_id]);
        s = bb_p2_sbox(s);
        rc_idx += 16;
        SIMD_EXT_MDS();
    }

    #undef SIMD_EXT_MDS

    // Write back
    states[perm_id * 16 + elem_id] = s;
}

// ============================================================================
// SIMD-cooperative Poseidon2 Goldilocks kernel (width=16)
//
// Port of the BabyBear SIMD pattern to 64-bit Goldilocks field.
// Uses 16 threads per permutation within a simdgroup. Each thread holds one
// state element. The internal layer sum uses simd shuffle tree reduction.
//
// Metal's simd_shuffle doesn't support uint64_t, so we split into two u32
// halves, shuffle each, and recombine.
// ============================================================================

// Helper: simd_shuffle for uint64_t via two uint32_t shuffles
inline uint64_t gl_simd_shuffle(uint64_t val, ushort lane) {
    uint32_t lo = (uint32_t)(val);
    uint32_t hi = (uint32_t)(val >> 32);
    lo = simd_shuffle(lo, lane);
    hi = simd_shuffle(hi, lane);
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

inline uint64_t gl_simd_shuffle_xor(uint64_t val, ushort mask) {
    uint32_t lo = (uint32_t)(val);
    uint32_t hi = (uint32_t)(val >> 32);
    lo = simd_shuffle_xor(lo, mask);
    hi = simd_shuffle_xor(hi, mask);
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

kernel void poseidon2_goldilocks_simd(
    device uint64_t *states [[buffer(0)]],
    device const uint64_t *round_constants [[buffer(1)]],
    constant uint32_t &n_perms [[buffer(2)]],
    constant uint32_t &n_external_rounds [[buffer(3)]],
    constant uint32_t &n_internal_rounds [[buffer(4)]],
    device const uint64_t *internal_diag [[buffer(5)]],
    uint tid [[thread_position_in_grid]],
    ushort simd_lane [[thread_index_in_simdgroup]])
{
    uint32_t perm_id = tid / 16;
    ushort elem_id = tid % 16;

    if (perm_id >= n_perms) return;

    uint64_t s = states[perm_id * 16 + elem_id];

    uint32_t rc_idx = 0;
    uint32_t half_ext = n_external_rounds / 2;
    uint64_t my_diag = internal_diag[elem_id];

    ushort perm_base = (ushort)((tid / 16) * 16) % 32;

    #define GL_SIMD_EXT_MDS() do { \
        ushort g_base = perm_base + (elem_id / 4) * 4; \
        uint64_t x0 = gl_simd_shuffle(s, g_base + 0); \
        uint64_t x1 = gl_simd_shuffle(s, g_base + 1); \
        uint64_t x2 = gl_simd_shuffle(s, g_base + 2); \
        uint64_t x3 = gl_simd_shuffle(s, g_base + 3); \
        uint64_t t01 = gl_add(x0, x1); \
        uint64_t t23 = gl_add(x2, x3); \
        uint64_t t0123 = gl_add(t01, t23); \
        uint64_t t01123 = gl_add(t0123, x1); \
        uint64_t t01233 = gl_add(t0123, x3); \
        ushort pig = elem_id % 4; \
        if (pig == 0) s = gl_add(t01123, t01); \
        else if (pig == 1) s = gl_add(t01123, gl_add(x2, x2)); \
        else if (pig == 2) s = gl_add(t01233, t23); \
        else s = gl_add(t01233, gl_add(x0, x0)); \
        ushort k = elem_id % 4; \
        uint64_t cs = gl_add( \
            gl_add(gl_simd_shuffle(s, perm_base + k), gl_simd_shuffle(s, perm_base + 4 + k)), \
            gl_add(gl_simd_shuffle(s, perm_base + 8 + k), gl_simd_shuffle(s, perm_base + 12 + k))); \
        s = gl_add(s, cs); \
    } while(0)

    GL_SIMD_EXT_MDS();

    for (uint32_t r = 0; r < half_ext; r++) {
        s = gl_add(s, round_constants[rc_idx + elem_id]);
        s = p2_sbox(s);
        rc_idx += 16;
        GL_SIMD_EXT_MDS();
    }

    for (uint32_t r = 0; r < n_internal_rounds; r++) {
        if (elem_id == 0) {
            s = gl_add(s, round_constants[rc_idx]);
            s = p2_sbox(s);
        }
        rc_idx += 1;

        uint64_t partial = s;
        partial = gl_add(partial, gl_simd_shuffle_xor(partial, 1));
        partial = gl_add(partial, gl_simd_shuffle_xor(partial, 2));
        partial = gl_add(partial, gl_simd_shuffle_xor(partial, 4));
        partial = gl_add(partial, gl_simd_shuffle_xor(partial, 8));
        uint64_t sum_all = gl_simd_shuffle(partial, perm_base);

        s = gl_add(gl_mul(s, my_diag), sum_all);
    }

    for (uint32_t r = 0; r < half_ext; r++) {
        s = gl_add(s, round_constants[rc_idx + elem_id]);
        s = p2_sbox(s);
        rc_idx += 16;
        GL_SIMD_EXT_MDS();
    }

    #undef GL_SIMD_EXT_MDS

    states[perm_id * 16 + elem_id] = s;
}
