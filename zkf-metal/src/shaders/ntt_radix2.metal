// NTT radix-2 DIT butterfly kernels
// Field arithmetic helpers are included before this file via concatenation

// Goldilocks NTT butterfly: one thread per butterfly
kernel void ntt_butterfly_goldilocks(
    device uint64_t *data [[buffer(0)]],
    device const uint64_t *twiddles [[buffer(1)]],
    constant uint32_t &stage [[buffer(2)]],
    constant uint32_t &n [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    uint32_t half_n = 1u << stage;
    uint32_t group_size = half_n << 1;
    uint32_t group = tid / half_n;
    uint32_t pos = tid % half_n;

    uint32_t idx0 = group * group_size + pos;
    uint32_t idx1 = idx0 + half_n;

    if (idx1 >= n) return;

    uint64_t a = data[idx0];
    uint64_t b = data[idx1];
    uint64_t w = twiddles[half_n + pos];

    uint64_t wb = gl_mul(w, b);
    data[idx0] = gl_add(a, wb);
    data[idx1] = gl_sub(a, wb);
}

// BabyBear NTT butterfly
kernel void ntt_butterfly_babybear(
    device uint32_t *data [[buffer(0)]],
    device const uint32_t *twiddles [[buffer(1)]],
    constant uint32_t &stage [[buffer(2)]],
    constant uint32_t &n [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    uint32_t half_n = 1u << stage;
    uint32_t group_size = half_n << 1;
    uint32_t group = tid / half_n;
    uint32_t pos = tid % half_n;

    uint32_t idx0 = group * group_size + pos;
    uint32_t idx1 = idx0 + half_n;

    if (idx1 >= n) return;

    uint32_t a = data[idx0];
    uint32_t b = data[idx1];
    uint32_t w = twiddles[half_n + pos];

    uint32_t wb = bb_mul(w, b);
    data[idx0] = bb_add(a, wb);
    data[idx1] = bb_sub(a, wb);
}

// Hybrid NTT: early stages in threadgroup shared memory, later stages in global.
// For N > 1024: first log2(tg_size) stages use fast shared memory with
// threadgroup_barrier, remaining stages use global memory with memory barriers.
kernel void ntt_hybrid_goldilocks(
    device uint64_t *data [[buffer(0)]],
    device const uint64_t *twiddles [[buffer(1)]],
    constant uint32_t &log_n [[buffer(2)]],
    constant uint32_t &log_tg_size [[buffer(3)]],
    threadgroup uint64_t *shared [[threadgroup(0)]],
    uint tid [[thread_position_in_threadgroup]],
    uint tg_size [[threads_per_threadgroup]],
    uint gid [[threadgroup_position_in_grid]])
{
    uint32_t n = 1u << log_n;
    uint32_t tg_n = 1u << log_tg_size;

    // Phase 1: Load tg_n elements into shared memory
    uint32_t block_id = gid;
    uint32_t block_size = tg_n;
    uint32_t global_offset = block_id * block_size;

    for (uint32_t i = tid; i < block_size; i += tg_size) {
        if (global_offset + i < n) {
            shared[i] = data[global_offset + i];
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Phase 2: Early stages in shared memory
    uint32_t shared_stages = min(log_tg_size, log_n);
    for (uint32_t stage = 0; stage < shared_stages; stage++) {
        uint32_t half_n = 1u << stage;
        uint32_t group_size = half_n << 1;

        for (uint32_t k = tid; k < block_size / 2; k += tg_size) {
            uint32_t group = k / half_n;
            uint32_t pos = k % half_n;
            uint32_t idx0 = group * group_size + pos;
            uint32_t idx1 = idx0 + half_n;

            if (idx1 < block_size) {
                uint64_t a = shared[idx0];
                uint64_t b = shared[idx1];
                uint64_t w = twiddles[half_n + pos];

                uint64_t wb = gl_mul(w, b);
                shared[idx0] = gl_add(a, wb);
                shared[idx1] = gl_sub(a, wb);
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // Write back to global
    for (uint32_t i = tid; i < block_size; i += tg_size) {
        if (global_offset + i < n) {
            data[global_offset + i] = shared[i];
        }
    }
    // Remaining stages handled by global-memory butterfly kernel dispatches
}

// Small NTT in threadgroup memory (Goldilocks, N <= 1024)
kernel void ntt_small_goldilocks(
    device uint64_t *data [[buffer(0)]],
    device const uint64_t *twiddles [[buffer(1)]],
    constant uint32_t &log_n [[buffer(2)]],
    threadgroup uint64_t *shared [[threadgroup(0)]],
    uint tid [[thread_position_in_threadgroup]],
    uint tg_size [[threads_per_threadgroup]],
    uint gid [[threadgroup_position_in_grid]])
{
    uint32_t n = 1u << log_n;
    uint32_t batch_offset = gid * n;

    for (uint32_t i = tid; i < n; i += tg_size) {
        shared[i] = data[batch_offset + i];
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint32_t stage = 0; stage < log_n; stage++) {
        uint32_t half_n = 1u << stage;
        uint32_t group_size = half_n << 1;

        for (uint32_t k = tid; k < n / 2; k += tg_size) {
            uint32_t group = k / half_n;
            uint32_t pos = k % half_n;
            uint32_t idx0 = group * group_size + pos;
            uint32_t idx1 = idx0 + half_n;

            uint64_t a = shared[idx0];
            uint64_t b = shared[idx1];
            uint64_t w = twiddles[half_n + pos];

            uint64_t wb = gl_mul(w, b);
            shared[idx0] = gl_add(a, wb);
            shared[idx1] = gl_sub(a, wb);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    for (uint32_t i = tid; i < n; i += tg_size) {
        data[batch_offset + i] = shared[i];
    }
}
