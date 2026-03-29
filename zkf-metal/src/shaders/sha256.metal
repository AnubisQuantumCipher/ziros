// Batch SHA-256 hashing on Metal GPU
// Each thread computes one SHA-256 hash of a fixed-length input.
//
// Standard FIPS 180-4 implementation.

#include <metal_stdlib>
using namespace metal;

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
constant uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sha256_sigma0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t sha256_sigma1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t sha256_gamma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t sha256_gamma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

// Read a big-endian uint32 from bytes
static inline uint32_t be32(device const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

// Write a big-endian uint32 to bytes
static inline void write_be32(device uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

// Batch SHA-256: each thread hashes one input of `input_len` bytes.
//
// Buffer layout:
//   buffer(0): inputs  — n_inputs * input_len bytes (contiguous)
//   buffer(1): outputs — n_inputs * 32 bytes (SHA-256 digests)
//   buffer(2): n_inputs (uint32_t)
//   buffer(3): input_len (uint32_t) — length of each input in bytes
kernel void batch_sha256(
    device const uint8_t *inputs [[buffer(0)]],
    device uint8_t *outputs [[buffer(1)]],
    constant uint32_t &n_inputs [[buffer(2)]],
    constant uint32_t &input_len [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_inputs) return;

    device const uint8_t *input = inputs + tid * input_len;
    device uint8_t *output = outputs + tid * 32;

    // Initialize hash state
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Pre-processing: pad to 512-bit blocks
    // Total padded length: input_len + 1 (0x80) + padding + 8 (length)
    uint64_t bit_len = (uint64_t)input_len * 8;
    uint32_t padded_len = ((input_len + 9 + 63) / 64) * 64;
    uint32_t n_blocks = padded_len / 64;

    for (uint32_t block = 0; block < n_blocks; block++) {
        uint32_t W[64];

        // Load 16 words from the padded message
        uint32_t block_start = block * 64;
        for (int i = 0; i < 16; i++) {
            uint32_t byte_pos = block_start + i * 4;
            uint32_t w = 0;
            for (int b = 0; b < 4; b++) {
                uint32_t pos = byte_pos + b;
                uint8_t val;
                if (pos < input_len) {
                    val = input[pos];
                } else if (pos == input_len) {
                    val = 0x80;
                } else if (pos >= padded_len - 8) {
                    // Big-endian 64-bit length in last 8 bytes
                    uint32_t len_offset = pos - (padded_len - 8);
                    val = (uint8_t)(bit_len >> (56 - len_offset * 8));
                } else {
                    val = 0;
                }
                w = (w << 8) | val;
            }
            W[i] = w;
        }

        // Extend to 64 words
        for (int i = 16; i < 64; i++) {
            W[i] = sha256_gamma1(W[i-2]) + W[i-7] + sha256_gamma0(W[i-15]) + W[i-16];
        }

        // Compression
        uint32_t a = h0, b = h1, c = h2, d = h3;
        uint32_t e = h4, f = h5, g = h6, h = h7;

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + sha256_sigma1(e) + sha256_ch(e, f, g) + K256[i] + W[i];
            uint32_t t2 = sha256_sigma0(a) + sha256_maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }

    // Write output (big-endian)
    write_be32(output +  0, h0);
    write_be32(output +  4, h1);
    write_be32(output +  8, h2);
    write_be32(output + 12, h3);
    write_be32(output + 16, h4);
    write_be32(output + 20, h5);
    write_be32(output + 24, h6);
    write_be32(output + 28, h7);
}
