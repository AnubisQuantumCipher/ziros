// Batch Keccak-256 hashing on Metal GPU
// Each thread computes one Keccak-256 hash of a fixed-length input.
//
// Implements the Keccak-f[1600] permutation with rate=1088, capacity=512.
// Output: 256-bit (32 bytes) digest per input.

#include <metal_stdlib>
using namespace metal;

// Keccak-f[1600] round constants
constant uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

// Rotation offsets for rho step
constant int KECCAK_ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

// Pi step permutation indices
constant int KECCAK_PI[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak-f[1600] permutation (24 rounds)
static inline void keccak_f1600(thread uint64_t *state) {
    for (int round = 0; round < 24; round++) {
        // Theta
        uint64_t C[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        uint64_t D[5];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        // Rho + Pi (combined)
        uint64_t tmp[25];
        for (int i = 0; i < 25; i++) {
            tmp[KECCAK_PI[i]] = rotl64(state[i], KECCAK_ROT[i]);
        }

        // Chi
        for (int y = 0; y < 5; y++) {
            int base = y * 5;
            uint64_t t0 = tmp[base + 0];
            uint64_t t1 = tmp[base + 1];
            uint64_t t2 = tmp[base + 2];
            uint64_t t3 = tmp[base + 3];
            uint64_t t4 = tmp[base + 4];
            state[base + 0] = t0 ^ (~t1 & t2);
            state[base + 1] = t1 ^ (~t2 & t3);
            state[base + 2] = t2 ^ (~t3 & t4);
            state[base + 3] = t3 ^ (~t4 & t0);
            state[base + 4] = t4 ^ (~t0 & t1);
        }

        // Iota
        state[0] ^= KECCAK_RC[round];
    }
}

// Batch Keccak-256: each thread hashes one input of `input_len` bytes.
//
// Buffer layout:
//   buffer(0): inputs  — n_inputs * input_len bytes
//   buffer(1): outputs — n_inputs * 32 bytes (Keccak-256 digests)
//   buffer(2): n_inputs (uint32_t)
//   buffer(3): input_len (uint32_t)
kernel void batch_keccak256(
    device const uint8_t *inputs [[buffer(0)]],
    device uint8_t *outputs [[buffer(1)]],
    constant uint32_t &n_inputs [[buffer(2)]],
    constant uint32_t &input_len [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_inputs) return;

    device const uint8_t *input = inputs + tid * input_len;
    device uint8_t *output = outputs + tid * 32;

    // Keccak state (5x5 x 64-bit = 1600 bits)
    uint64_t state[25] = {};

    // Rate in bytes for Keccak-256: (1600 - 512) / 8 = 136 bytes
    const uint32_t rate = 136;

    // Absorb phase: process rate-sized blocks
    uint32_t absorbed = 0;
    while (absorbed + rate <= input_len) {
        // XOR rate bytes into state (as little-endian uint64)
        for (uint32_t i = 0; i < rate / 8; i++) {
            uint64_t word = 0;
            for (int b = 0; b < 8; b++) {
                word |= (uint64_t)input[absorbed + i * 8 + b] << (b * 8);
            }
            state[i] ^= word;
        }
        keccak_f1600(state);
        absorbed += rate;
    }

    // Final block with padding
    // Keccak padding: append 0x01, then zeros, then 0x80 at end of rate block
    uint8_t last_block[136] = {};
    uint32_t remaining = input_len - absorbed;
    for (uint32_t i = 0; i < remaining; i++) {
        last_block[i] = input[absorbed + i];
    }
    last_block[remaining] = 0x01;       // Keccak domain separator
    last_block[rate - 1] |= 0x80;       // Final bit of padding

    for (uint32_t i = 0; i < rate / 8; i++) {
        uint64_t word = 0;
        for (int b = 0; b < 8; b++) {
            word |= (uint64_t)last_block[i * 8 + b] << (b * 8);
        }
        state[i] ^= word;
    }
    keccak_f1600(state);

    // Squeeze: extract 32 bytes (4 uint64s) in little-endian
    for (int i = 0; i < 4; i++) {
        uint64_t w = state[i];
        for (int b = 0; b < 8; b++) {
            output[i * 8 + b] = (uint8_t)(w >> (b * 8));
        }
    }
}
