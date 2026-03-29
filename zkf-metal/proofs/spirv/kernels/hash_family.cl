typedef unsigned int uint;
typedef unsigned long ulong;

inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

inline uint hash_mix(uint x, uint y, uint round) {
    return rotr32(x ^ y ^ round, 7) + (x << 3);
}

__kernel void batch_sha256(
    __global uint* state,
    __global const uint* input_words,
    const uint rounds,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        uint acc = state[gid];
        for (uint round = 0; round < rounds; ++round) {
            acc = hash_mix(acc, input_words[(gid + round) % count], round);
        }
        state[gid] = acc;
    }
}

__kernel void batch_keccak256(
    __global uint* state,
    __global const uint* input_words,
    const uint rounds,
    const uint count
) {
    size_t gid = get_global_id(0);
    if (gid < count) {
        uint acc = state[gid];
        for (uint round = 0; round < rounds; ++round) {
            acc = rotr32(acc + input_words[(gid + round) % count] + round, 11) ^ (acc << 1);
        }
        state[gid] = acc;
    }
}
