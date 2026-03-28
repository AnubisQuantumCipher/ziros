#include <metal_stdlib>
using namespace metal;

// ============================================================================
// BN254 MSM: Unified shader for Multi-Scalar Multiplication
// Includes: Fq field arithmetic, G1 projective curve ops, Pippenger kernels
// ============================================================================

// BN254 BASE FIELD (Fq) — used for point coordinates
// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
// Montgomery form: all field elements stored as a * R mod p, where R = 2^256

struct Fp {
    uint64_t limbs[4];
};

// Fq modulus
constant Fp FQ_P = {{
    0x3c208c16d87cfd47ULL,
    0x97816a916871ca8dULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL
}};

// R mod p (Montgomery form of 1)
constant Fp FQ_ONE = {{
    0xd35d438dc58f0d9dULL,
    0x0a78eb28f5c70b3dULL,
    0x666ea36f7879462cULL,
    0x0e0a77c19a07df2fULL
}};

// -p^(-1) mod 2^64
constant uint64_t FQ_INV = 0x87d20782e4866389ULL;

// R^2 mod p (for converting to Montgomery form)
constant Fp FQ_R2 = {{
    0xf32cfc5b538afa89ULL,
    0xb5e71911d44501fbULL,
    0x47ab1eff0a417ff6ULL,
    0x06d89f71cab8351fULL
}};

// --- Fp arithmetic primitives ---

static inline uint64_t adc(uint64_t a, uint64_t b, thread uint64_t &carry) {
    uint64_t lo = a + b;
    uint64_t c1 = (lo < a) ? 1ULL : 0ULL;
    uint64_t result = lo + carry;
    uint64_t c2 = (result < lo) ? 1ULL : 0ULL;
    carry = c1 + c2;
    return result;
}

static inline uint64_t sbb(uint64_t a, uint64_t b, thread uint64_t &borrow) {
    uint64_t lo = a - b;
    uint64_t b1 = (lo > a) ? 1ULL : 0ULL;
    uint64_t result = lo - borrow;
    uint64_t b2 = (result > lo) ? 1ULL : 0ULL;
    borrow = b1 + b2;
    return result;
}

static inline void mul64(uint64_t a, uint64_t b, thread uint64_t &hi, thread uint64_t &lo) {
    uint64_t a_lo = a & 0xFFFFFFFFULL;
    uint64_t a_hi = a >> 32;
    uint64_t b_lo = b & 0xFFFFFFFFULL;
    uint64_t b_hi = b >> 32;

    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;

    uint64_t mid = p1 + (p0 >> 32);
    uint64_t mid_carry = (mid < p1) ? 1ULL : 0ULL;
    mid = mid + p2;
    mid_carry += (mid < p2) ? 1ULL : 0ULL;

    lo = (p0 & 0xFFFFFFFFULL) | (mid << 32);
    hi = p3 + (mid >> 32) + (mid_carry << 32);
}

// Multiply-accumulate with carry: acc += a * b + carry_in; returns carry_out
static inline void mac(uint64_t a, uint64_t b, thread uint64_t &acc, thread uint64_t &carry) {
    uint64_t hi, lo;
    mul64(a, b, hi, lo);
    uint64_t c1 = 0ULL;
    acc = adc(acc, lo, c1);     // acc += lo
    uint64_t c2 = 0ULL;
    acc = adc(acc, carry, c2);  // acc += carry_in
    carry = hi + c1 + c2;      // carry_out = hi + overflows
}

static inline Fp fp_add(Fp a, Fp b) {
    uint64_t carry = 0;
    Fp r;
    r.limbs[0] = adc(a.limbs[0], b.limbs[0], carry);
    r.limbs[1] = adc(a.limbs[1], b.limbs[1], carry);
    r.limbs[2] = adc(a.limbs[2], b.limbs[2], carry);
    r.limbs[3] = adc(a.limbs[3], b.limbs[3], carry);

    uint64_t borrow = 0;
    Fp s;
    s.limbs[0] = sbb(r.limbs[0], FQ_P.limbs[0], borrow);
    s.limbs[1] = sbb(r.limbs[1], FQ_P.limbs[1], borrow);
    s.limbs[2] = sbb(r.limbs[2], FQ_P.limbs[2], borrow);
    s.limbs[3] = sbb(r.limbs[3], FQ_P.limbs[3], borrow);
    uint64_t overflow_borrow = 0;
    sbb(carry, 0ULL, overflow_borrow);
    borrow = borrow | overflow_borrow;

    if (borrow) return r;
    return s;
}

static inline Fp fp_sub(Fp a, Fp b) {
    uint64_t borrow = 0;
    Fp r;
    r.limbs[0] = sbb(a.limbs[0], b.limbs[0], borrow);
    r.limbs[1] = sbb(a.limbs[1], b.limbs[1], borrow);
    r.limbs[2] = sbb(a.limbs[2], b.limbs[2], borrow);
    r.limbs[3] = sbb(a.limbs[3], b.limbs[3], borrow);

    if (borrow) {
        uint64_t carry = 0;
        r.limbs[0] = adc(r.limbs[0], FQ_P.limbs[0], carry);
        r.limbs[1] = adc(r.limbs[1], FQ_P.limbs[1], carry);
        r.limbs[2] = adc(r.limbs[2], FQ_P.limbs[2], carry);
        r.limbs[3] = adc(r.limbs[3], FQ_P.limbs[3], carry);
    }
    return r;
}

static inline Fp fp_mul(Fp a, Fp b) {
    // 4-limb schoolbook multiply with interleaved Montgomery reduction
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;

    for (int i = 0; i < 4; i++) {
        // Multiply-accumulate: t += a * b[i]
        uint64_t carry = 0;
        mac(a.limbs[0], b.limbs[i], t0, carry);
        mac(a.limbs[1], b.limbs[i], t1, carry);
        mac(a.limbs[2], b.limbs[i], t2, carry);
        mac(a.limbs[3], b.limbs[i], t3, carry);
        uint64_t c2 = 0;
        t4 = adc(t4, carry, c2);

        // Montgomery reduction: m = t0 * INV mod 2^64
        uint64_t m_hi, m;
        mul64(t0, FQ_INV, m_hi, m);

        // t += p * m (and shift right by 64)
        carry = 0;
        mac(FQ_P.limbs[0], m, t0, carry); // t0 becomes 0 (by construction)
        mac(FQ_P.limbs[1], m, t1, carry);
        mac(FQ_P.limbs[2], m, t2, carry);
        mac(FQ_P.limbs[3], m, t3, carry);
        uint64_t rc_carry = 0;
        t4 = adc(t4, carry, rc_carry);

        // Shift down by one limb
        t0 = t1;
        t1 = t2;
        t2 = t3;
        t3 = t4;
        t4 = c2 + rc_carry;
    }

    Fp result = {{t0, t1, t2, t3}};

    // Final conditional subtraction
    uint64_t borrow = 0;
    Fp s;
    s.limbs[0] = sbb(t0, FQ_P.limbs[0], borrow);
    s.limbs[1] = sbb(t1, FQ_P.limbs[1], borrow);
    s.limbs[2] = sbb(t2, FQ_P.limbs[2], borrow);
    s.limbs[3] = sbb(t3, FQ_P.limbs[3], borrow);

    if (borrow) return result;
    return s;
}

static inline bool fp_is_zero(Fp a) {
    return (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]) == 0;
}

static inline Fp fp_zero() {
    Fp z = {{0, 0, 0, 0}};
    return z;
}

// --- G1 Projective point operations ---
// Jacobian coordinates: affine (x,y) = (X/Z^2, Y/Z^3)
// Identity: Z = 0

struct G1Proj {
    Fp x, y, z;
};

static inline G1Proj g1_identity() {
    G1Proj p;
    p.x = FQ_ONE;  // doesn't matter, Z=0
    p.y = FQ_ONE;
    p.z = fp_zero();
    return p;
}

static inline bool g1_is_identity(G1Proj p) {
    return fp_is_zero(p.z);
}

// Point doubling (Jacobian, a=0 for BN254)
static inline G1Proj g1_double(G1Proj p) {
    if (g1_is_identity(p)) return p;

    Fp a = fp_mul(p.x, p.x);         // A = X^2
    Fp b = fp_mul(p.y, p.y);         // B = Y^2
    Fp c = fp_mul(b, b);             // C = B^2

    // D = 2*((X+B)^2 - A - C)
    Fp xb = fp_add(p.x, b);
    Fp d = fp_mul(xb, xb);
    d = fp_sub(d, a);
    d = fp_sub(d, c);
    d = fp_add(d, d);

    // E = 3*A (a=0 for BN254, so 3a*Z^4 = 0)
    Fp e = fp_add(a, fp_add(a, a));

    // F = E^2
    Fp f = fp_mul(e, e);

    // X3 = F - 2*D
    G1Proj r;
    r.x = fp_sub(f, fp_add(d, d));

    // Y3 = E*(D - X3) - 8*C
    Fp c8 = fp_add(c, c);
    c8 = fp_add(c8, c8);
    c8 = fp_add(c8, c8);
    r.y = fp_mul(e, fp_sub(d, r.x));
    r.y = fp_sub(r.y, c8);

    // Z3 = 2*Y*Z
    r.z = fp_mul(p.y, p.z);
    r.z = fp_add(r.z, r.z);

    return r;
}

// Mixed addition: Jacobian + affine (Z2 = 1)
static inline G1Proj g1_add_mixed(G1Proj p, Fp qx, Fp qy) {
    if (g1_is_identity(p)) {
        G1Proj r;
        r.x = qx;
        r.y = qy;
        r.z = FQ_ONE;
        return r;
    }

    Fp z1z1 = fp_mul(p.z, p.z);
    Fp u2 = fp_mul(qx, z1z1);
    Fp z1_cubed = fp_mul(p.z, z1z1);
    Fp s2 = fp_mul(qy, z1_cubed);

    Fp h = fp_sub(u2, p.x);
    if (fp_is_zero(h)) {
        Fp s_diff = fp_sub(s2, p.y);
        if (fp_is_zero(s_diff)) {
            return g1_double(p);
        }
        return g1_identity();
    }

    Fp hh = fp_mul(h, h);
    Fp i = fp_add(hh, hh);
    i = fp_add(i, i);
    Fp j = fp_mul(h, i);
    Fp rr = fp_sub(s2, p.y);
    rr = fp_add(rr, rr);
    Fp v = fp_mul(p.x, i);

    G1Proj result;
    result.x = fp_mul(rr, rr);
    result.x = fp_sub(result.x, j);
    result.x = fp_sub(result.x, fp_add(v, v));

    result.y = fp_mul(rr, fp_sub(v, result.x));
    Fp y1j = fp_mul(p.y, j);
    y1j = fp_add(y1j, y1j);
    result.y = fp_sub(result.y, y1j);

    result.z = fp_add(p.z, h);
    result.z = fp_mul(result.z, result.z);
    result.z = fp_sub(result.z, z1z1);
    result.z = fp_sub(result.z, hh);

    return result;
}

// Full Jacobian + Jacobian addition (for SIMD reduction)
static inline G1Proj g1_add_proj(G1Proj p, G1Proj q) {
    if (g1_is_identity(p)) return q;
    if (g1_is_identity(q)) return p;

    Fp z1z1 = fp_mul(p.z, p.z);
    Fp z2z2 = fp_mul(q.z, q.z);
    Fp u1 = fp_mul(p.x, z2z2);
    Fp u2 = fp_mul(q.x, z1z1);
    Fp s1 = fp_mul(fp_mul(p.y, q.z), z2z2);
    Fp s2 = fp_mul(fp_mul(q.y, p.z), z1z1);

    Fp h = fp_sub(u2, u1);
    Fp rr = fp_sub(s2, s1);

    if (fp_is_zero(h)) {
        if (fp_is_zero(rr)) return g1_double(p);
        return g1_identity();
    }

    Fp hh = fp_mul(h, h);
    Fp hhh = fp_mul(h, hh);
    Fp v = fp_mul(u1, hh);

    G1Proj result;
    rr = fp_add(rr, rr);
    result.x = fp_mul(rr, rr);
    result.x = fp_sub(result.x, hhh);
    result.x = fp_sub(result.x, fp_add(v, v));

    result.y = fp_mul(rr, fp_sub(v, result.x));
    Fp s1hhh = fp_mul(s1, hhh);
    s1hhh = fp_add(s1hhh, s1hhh);
    result.y = fp_sub(result.y, s1hhh);

    result.z = fp_mul(fp_add(p.z, q.z), fp_add(p.z, q.z));
    result.z = fp_sub(result.z, z1z1);
    result.z = fp_sub(result.z, z2z2);
    result.z = fp_mul(result.z, h);

    return result;
}

// --- Scalar operations ---

struct Scalar256 {
    uint64_t limbs[4];
};

static inline uint32_t extract_window(Scalar256 s, uint32_t window_idx, uint32_t c) {
    uint32_t bit_offset = window_idx * c;
    uint32_t limb_idx = bit_offset / 64;
    uint32_t bit_in_limb = bit_offset % 64;
    uint32_t mask = (1u << c) - 1u;

    if (limb_idx >= 4) return 0;

    uint64_t val = s.limbs[limb_idx] >> bit_in_limb;
    if (bit_in_limb + c > 64 && limb_idx + 1 < 4) {
        val |= s.limbs[limb_idx + 1] << (64 - bit_in_limb);
    }
    return (uint32_t)(val) & mask;
}

// --- MSM Kernels ---

// Kernel: Bucket sort — each thread writes its bucket assignment per window
kernel void msm_bucket_assign(
    device const uint64_t *scalars [[buffer(0)]],      // n_points * 4 uint64s
    device uint32_t *point_bucket_map [[buffer(1)]],   // n_points * num_windows
    constant uint32_t &n_points [[buffer(2)]],
    constant uint32_t &c [[buffer(3)]],
    constant uint32_t &num_windows [[buffer(4)]],
    constant uint32_t &window_offset [[buffer(5)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n_points) return;

    Scalar256 s;
    s.limbs[0] = scalars[tid * 4 + 0];
    s.limbs[1] = scalars[tid * 4 + 1];
    s.limbs[2] = scalars[tid * 4 + 2];
    s.limbs[3] = scalars[tid * 4 + 3];

    for (uint32_t w = 0; w < num_windows; w++) {
        uint32_t bucket_idx = extract_window(s, window_offset + w, c);
        point_bucket_map[tid * num_windows + w] = bucket_idx;
    }
}

// Kernel: Bucket accumulation — each thread processes one bucket
// Iterates over all points, adding those assigned to this bucket
kernel void msm_bucket_acc(
    device const uint64_t *bases_x [[buffer(0)]],      // n_points * 4 uint64s (Fp in Montgomery form)
    device const uint64_t *bases_y [[buffer(1)]],      // n_points * 4 uint64s
    device const uint32_t *point_bucket_map [[buffer(2)]],
    device uint64_t *bucket_results [[buffer(3)]],     // total_buckets * 12 uint64s (G1Proj)
    constant uint32_t &n_points [[buffer(4)]],
    constant uint32_t &c [[buffer(5)]],
    constant uint32_t &num_windows [[buffer(6)]],
    uint tid [[thread_position_in_grid]])
{
    uint32_t num_buckets = 1u << c;
    uint32_t total_buckets = num_windows * num_buckets;
    if (tid >= total_buckets) return;

    uint32_t window = tid / num_buckets;
    uint32_t bucket = tid % num_buckets;

    // Bucket 0 = identity (scalar window is zero, point contributes nothing)
    if (bucket == 0) {
        uint32_t out = tid * 12;
        for (int i = 0; i < 12; i++) bucket_results[out + i] = 0;
        return;
    }

    G1Proj acc = g1_identity();

    for (uint32_t i = 0; i < n_points; i++) {
        if (point_bucket_map[i * num_windows + window] == bucket) {
            Fp px, py;
            for (int j = 0; j < 4; j++) {
                px.limbs[j] = bases_x[i * 4 + j];
                py.limbs[j] = bases_y[i * 4 + j];
            }
            acc = g1_add_mixed(acc, px, py);
        }
    }

    // Write projective result (X, Y, Z as 4×u64 each = 12 u64s)
    uint32_t out = tid * 12;
    for (int j = 0; j < 4; j++) {
        bucket_results[out + j]     = acc.x.limbs[j];
        bucket_results[out + 4 + j] = acc.y.limbs[j];
        bucket_results[out + 8 + j] = acc.z.limbs[j];
    }
}

// SIMD-cooperative bucket accumulation: multiple threads per bucket
// Each thread in a SIMD group handles a strided subset of points for one bucket,
// then results are reduced within the SIMD group.
kernel void msm_bucket_acc_simd(
    device const uint64_t *bases_x [[buffer(0)]],
    device const uint64_t *bases_y [[buffer(1)]],
    device const uint32_t *point_bucket_map [[buffer(2)]],
    device uint64_t *bucket_results [[buffer(3)]],
    constant uint32_t &n_points [[buffer(4)]],
    constant uint32_t &c [[buffer(5)]],
    constant uint32_t &num_windows [[buffer(6)]],
    uint tid [[thread_position_in_grid]],
    ushort simd_lane [[thread_index_in_simdgroup]],
    ushort simd_size [[threads_per_simdgroup]])
{
    // Each SIMD group handles one bucket
    uint32_t num_buckets = 1u << c;
    uint32_t total_buckets = num_windows * num_buckets;
    uint32_t bucket_global_id = tid / simd_size;

    if (bucket_global_id >= total_buckets) return;

    uint32_t window = bucket_global_id / num_buckets;
    uint32_t bucket = bucket_global_id % num_buckets;

    if (bucket == 0) {
        if (simd_lane == 0) {
            uint32_t out = bucket_global_id * 12;
            for (int i = 0; i < 12; i++) bucket_results[out + i] = 0;
        }
        return;
    }

    // Each lane accumulates a strided subset of points
    G1Proj acc = g1_identity();
    for (uint32_t i = simd_lane; i < n_points; i += simd_size) {
        if (point_bucket_map[i * num_windows + window] == bucket) {
            Fp px, py;
            for (int j = 0; j < 4; j++) {
                px.limbs[j] = bases_x[i * 4 + j];
                py.limbs[j] = bases_y[i * 4 + j];
            }
            acc = g1_add_mixed(acc, px, py);
        }
    }

    // Reduce across SIMD lanes: lane 0 accumulates all results
    // Metal simd_shuffle doesn't support uint64_t, so we split into two u32 halves
    for (ushort stride = 1; stride < simd_size; stride *= 2) {
        if (simd_lane % (stride * 2) == 0) {
            // Get partner's accumulator via u32 shuffles on each limb half
            G1Proj partner;
            for (int j = 0; j < 4; j++) {
                uint32_t xl = simd_shuffle_xor((uint32_t)(acc.x.limbs[j]), stride);
                uint32_t xh = simd_shuffle_xor((uint32_t)(acc.x.limbs[j] >> 32), stride);
                partner.x.limbs[j] = ((uint64_t)xh << 32) | (uint64_t)xl;

                uint32_t yl = simd_shuffle_xor((uint32_t)(acc.y.limbs[j]), stride);
                uint32_t yh = simd_shuffle_xor((uint32_t)(acc.y.limbs[j] >> 32), stride);
                partner.y.limbs[j] = ((uint64_t)yh << 32) | (uint64_t)yl;

                uint32_t zl = simd_shuffle_xor((uint32_t)(acc.z.limbs[j]), stride);
                uint32_t zh = simd_shuffle_xor((uint32_t)(acc.z.limbs[j] >> 32), stride);
                partner.z.limbs[j] = ((uint64_t)zh << 32) | (uint64_t)zl;
            }
            if (!g1_is_identity(partner)) {
                if (g1_is_identity(acc)) {
                    acc = partner;
                } else {
                    // Projective addition (both non-identity)
                    acc = g1_add_proj(acc, partner);
                }
            }
        } else {
            // Non-participating lanes still need to execute the shuffles
            for (int j = 0; j < 4; j++) {
                simd_shuffle_xor((uint32_t)(acc.x.limbs[j]), stride);
                simd_shuffle_xor((uint32_t)(acc.x.limbs[j] >> 32), stride);
                simd_shuffle_xor((uint32_t)(acc.y.limbs[j]), stride);
                simd_shuffle_xor((uint32_t)(acc.y.limbs[j] >> 32), stride);
                simd_shuffle_xor((uint32_t)(acc.z.limbs[j]), stride);
                simd_shuffle_xor((uint32_t)(acc.z.limbs[j] >> 32), stride);
            }
        }
    }

    // Lane 0 writes the result
    if (simd_lane == 0) {
        uint32_t out = bucket_global_id * 12;
        for (int j = 0; j < 4; j++) {
            bucket_results[out + j]     = acc.x.limbs[j];
            bucket_results[out + 4 + j] = acc.y.limbs[j];
            bucket_results[out + 8 + j] = acc.z.limbs[j];
        }
    }
}
