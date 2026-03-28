// NTT radix-2 DIT butterfly kernels for BN254 scalar field (Fr)
// Field arithmetic included via concatenation of field_bn254_fr.metal

// BN254 Fr NTT butterfly: one thread per butterfly
// Each Fr element is 4 x uint64_t (32 bytes) in Montgomery form
kernel void ntt_butterfly_bn254(
    device uint64_t *data [[buffer(0)]],           // n * 4 uint64s (Fr elements)
    device const uint64_t *twiddles [[buffer(1)]], // twiddle factors, 4 uint64s each
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

    // Load Fr elements (4 limbs each)
    Fr a, b, w;
    uint32_t off0 = idx0 * 4;
    uint32_t off1 = idx1 * 4;
    uint32_t tw_off = (half_n + pos) * 4;

    for (int j = 0; j < 4; j++) {
        a.limbs[j] = data[off0 + j];
        b.limbs[j] = data[off1 + j];
        w.limbs[j] = twiddles[tw_off + j];
    }

    Fr wb = fr_mul(w, b);
    Fr out0 = fr_add(a, wb);
    Fr out1 = fr_sub(a, wb);

    for (int j = 0; j < 4; j++) {
        data[off0 + j] = out0.limbs[j];
        data[off1 + j] = out1.limbs[j];
    }
}

// Small NTT fully in threadgroup memory (BN254 Fr, N <= 256)
// Limit is lower than Goldilocks because each element is 32 bytes vs 8
kernel void ntt_small_bn254(
    device uint64_t *data [[buffer(0)]],
    device const uint64_t *twiddles [[buffer(1)]],
    constant uint32_t &log_n [[buffer(2)]],
    threadgroup uint64_t *shared [[threadgroup(0)]],  // n * 4 uint64s
    uint tid [[thread_position_in_threadgroup]],
    uint tg_size [[threads_per_threadgroup]],
    uint gid [[threadgroup_position_in_grid]])
{
    uint32_t n = 1u << log_n;
    uint32_t batch_offset = gid * n * 4;  // each element is 4 uint64s

    // Load into shared memory
    uint32_t total_words = n * 4;
    for (uint32_t i = tid; i < total_words; i += tg_size) {
        shared[i] = data[batch_offset + i];
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // NTT stages
    for (uint32_t stage = 0; stage < log_n; stage++) {
        uint32_t half_n_s = 1u << stage;
        uint32_t group_size = half_n_s << 1;

        for (uint32_t k = tid; k < n / 2; k += tg_size) {
            uint32_t group = k / half_n_s;
            uint32_t pos = k % half_n_s;
            uint32_t idx0 = group * group_size + pos;
            uint32_t idx1 = idx0 + half_n_s;

            Fr a, b, w;
            uint32_t off0 = idx0 * 4;
            uint32_t off1 = idx1 * 4;
            uint32_t tw_off = (half_n_s + pos) * 4;

            for (int j = 0; j < 4; j++) {
                a.limbs[j] = shared[off0 + j];
                b.limbs[j] = shared[off1 + j];
                w.limbs[j] = twiddles[tw_off + j];
            }

            Fr wb = fr_mul(w, b);
            Fr out0 = fr_add(a, wb);
            Fr out1 = fr_sub(a, wb);

            for (int j = 0; j < 4; j++) {
                shared[off0 + j] = out0.limbs[j];
                shared[off1 + j] = out1.limbs[j];
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // Write back
    for (uint32_t i = tid; i < total_words; i += tg_size) {
        data[batch_offset + i] = shared[i];
    }
}

// Hybrid NTT: early stages in shared memory, later stages in global
// For larger NTTs that don't fit entirely in threadgroup memory
kernel void ntt_hybrid_bn254(
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
    uint32_t block_size = tg_n;
    uint32_t global_offset = gid * block_size * 4;  // 4 uint64s per element

    // Load block into shared memory
    uint32_t total_words = block_size * 4;
    for (uint32_t i = tid; i < total_words; i += tg_size) {
        uint32_t gi = global_offset + i;
        if (gi < n * 4) {
            shared[i] = data[gi];
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Early stages in shared memory
    uint32_t shared_stages = min(log_tg_size, log_n);
    for (uint32_t stage = 0; stage < shared_stages; stage++) {
        uint32_t half_n_s = 1u << stage;
        uint32_t group_size = half_n_s << 1;

        for (uint32_t k = tid; k < block_size / 2; k += tg_size) {
            uint32_t group = k / half_n_s;
            uint32_t pos = k % half_n_s;
            uint32_t idx0 = group * group_size + pos;
            uint32_t idx1 = idx0 + half_n_s;

            if (idx1 < block_size) {
                Fr a, b, w;
                uint32_t off0 = idx0 * 4;
                uint32_t off1 = idx1 * 4;
                uint32_t tw_off = (half_n_s + pos) * 4;

                for (int j = 0; j < 4; j++) {
                    a.limbs[j] = shared[off0 + j];
                    b.limbs[j] = shared[off1 + j];
                    w.limbs[j] = twiddles[tw_off + j];
                }

                Fr wb = fr_mul(w, b);
                Fr out0 = fr_add(a, wb);
                Fr out1 = fr_sub(a, wb);

                for (int j = 0; j < 4; j++) {
                    shared[off0 + j] = out0.limbs[j];
                    shared[off1 + j] = out1.limbs[j];
                }
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // Write back to global
    for (uint32_t i = tid; i < total_words; i += tg_size) {
        uint32_t gi = global_offset + i;
        if (gi < n * 4) {
            data[gi] = shared[i];
        }
    }
}
