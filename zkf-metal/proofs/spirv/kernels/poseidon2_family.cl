typedef unsigned int uint;
typedef unsigned long ulong;

inline ulong poseidon_mix(ulong x, ulong rc, uint round) {
    ulong y = x + rc + (ulong) round;
    return (y << 7) | (y >> (64 - 7));
}

__kernel void poseidon2_goldilocks(
    __global ulong* state,
    __global const ulong* round_constants,
    const uint rounds,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        ulong acc = state[gid];
        for (uint round = 0; round < rounds; ++round) {
            acc = poseidon_mix(acc, round_constants[gid % rounds], round);
        }
        state[gid] = acc;
    }
}

__kernel void poseidon2_babybear(
    __global ulong* state,
    __global const ulong* round_constants,
    const uint rounds,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        ulong acc = state[gid];
        for (uint round = 0; round < rounds; ++round) {
            acc = poseidon_mix(acc ^ (ulong) gid, round_constants[gid % rounds], round);
        }
        state[gid] = acc;
    }
}

__kernel void poseidon2_babybear_simd(
    __global ulong* state,
    __global const ulong* round_constants,
    const uint rounds,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        ulong acc = state[gid];
        for (uint round = 0; round < rounds; ++round) {
            acc = poseidon_mix(acc + (ulong) gid, round_constants[gid % rounds], round);
        }
        state[gid] = acc;
    }
}

__kernel void poseidon2_goldilocks_simd(
    __global ulong* state,
    __global const ulong* round_constants,
    const uint rounds,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        ulong acc = state[gid];
        for (uint round = 0; round < rounds; ++round) {
            acc = poseidon_mix(acc + (ulong) (gid << 1), round_constants[gid % rounds], round);
        }
        state[gid] = acc;
    }
}
