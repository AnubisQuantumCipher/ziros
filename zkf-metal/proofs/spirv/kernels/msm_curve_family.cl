typedef unsigned int uint;
typedef unsigned long ulong;

inline ulong mul_accumulate(ulong base, ulong scalar, ulong acc, uint lane) {
    return acc + (base * (scalar + 1UL)) + (ulong) lane;
}

__kernel void msm_bucket_assign(
    __global ulong* buckets,
    __global const ulong* scalars,
    const uint bucket_count,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        buckets[gid % bucket_count] = scalars[gid] + (ulong) gid;
    }
}

__kernel void msm_bucket_acc(
    __global ulong* accumulators,
    __global const ulong* bases,
    __global const ulong* scalars,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        accumulators[gid] = mul_accumulate(bases[gid], scalars[gid], accumulators[gid], (uint) gid);
    }
}

__kernel void msm_bucket_acc_simd(
    __global ulong* accumulators,
    __global const ulong* bases,
    __global const ulong* scalars,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        accumulators[gid] = mul_accumulate(bases[gid], scalars[gid] ^ (ulong) gid, accumulators[gid], (uint) gid);
    }
}

__kernel void msm_bucket_acc_naf(
    __global ulong* accumulators,
    __global const ulong* bases,
    __global const ulong* scalars,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        ulong signed_like = (gid & 1U) == 0 ? scalars[gid] : ~scalars[gid];
        accumulators[gid] = mul_accumulate(bases[gid], signed_like, accumulators[gid], (uint) gid);
    }
}
