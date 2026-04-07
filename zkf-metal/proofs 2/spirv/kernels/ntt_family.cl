typedef unsigned int uint;
typedef unsigned long ulong;

inline ulong mix_lane(ulong left, ulong right, uint stage, uint lane) {
    return left + right + ((ulong) stage << 16) + (ulong) lane;
}

__kernel void ntt_butterfly_goldilocks(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = mix_lane(values[gid], twiddles[gid], stage, (uint) gid);
    }
}

__kernel void ntt_butterfly_babybear(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = values[gid] ^ (twiddles[gid] + ((ulong) stage << 8));
    }
}

__kernel void ntt_hybrid_goldilocks(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = values[gid] + twiddles[gid] + (ulong) stage;
    }
}

__kernel void ntt_small_goldilocks(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = values[gid] + twiddles[gid] + (ulong) (stage + 1);
    }
}

__kernel void ntt_butterfly_bn254(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = values[gid] + (twiddles[gid] << 1) + (ulong) stage;
    }
}

__kernel void ntt_small_bn254(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = values[gid] ^ (twiddles[gid] + (ulong) stage);
    }
}

__kernel void ntt_hybrid_bn254(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = mix_lane(values[gid], twiddles[gid], stage, (uint) gid ^ 1U);
    }
}

__kernel void ntt_butterfly_goldilocks_batch(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = values[gid] + twiddles[gid] + ((ulong) stage << 4);
    }
}

__kernel void ntt_butterfly_babybear_batch(
    __global ulong* values,
    __global const ulong* twiddles,
    const uint stage,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        values[gid] = values[gid] ^ (twiddles[gid] + ((ulong) stage << 4));
    }
}
