#include <metal_stdlib>
using namespace metal;

// ============================================================================
// BN254 SCALAR FIELD (Fr) — used for NTT on Groth16 QAP witness polynomials
// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// Montgomery form: all field elements stored as a * R mod r, where R = 2^256
// ============================================================================

struct Fr {
    uint64_t limbs[4];
};

// Fr modulus
constant Fr FR_R = {{
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL
}};

// R mod r (Montgomery form of 1)
constant Fr FR_ONE = {{
    0xac96341c4ffffffbULL,
    0x36fc76959f60cd29ULL,
    0x666ea36f7879462eULL,
    0x0e0a77c19a07df2fULL
}};

// -r^(-1) mod 2^64
constant uint64_t FR_INV = 0xc2e1f593efffffffULL;

// R^2 mod r (for converting to Montgomery form)
constant Fr FR_R2 = {{
    0x1bb8e645ae216da7ULL,
    0x53fe3ab1e35c59e3ULL,
    0x8c49833d53bb8085ULL,
    0x0216d0b17f4e44a5ULL
}};

// --- Fr arithmetic primitives ---
// Reuse the same adc/sbb/mul64/mac patterns from msm_bn254.metal
// but with Fr-specific modulus constants.

static inline uint64_t fr_adc(uint64_t a, uint64_t b, thread uint64_t &carry) {
    uint64_t lo = a + b;
    uint64_t c1 = (lo < a) ? 1ULL : 0ULL;
    uint64_t result = lo + carry;
    uint64_t c2 = (result < lo) ? 1ULL : 0ULL;
    carry = c1 + c2;
    return result;
}

static inline uint64_t fr_sbb(uint64_t a, uint64_t b, thread uint64_t &borrow) {
    uint64_t lo = a - b;
    uint64_t b1 = (lo > a) ? 1ULL : 0ULL;
    uint64_t result = lo - borrow;
    uint64_t b2 = (result > lo) ? 1ULL : 0ULL;
    borrow = b1 + b2;
    return result;
}

static inline void fr_mul64(uint64_t a, uint64_t b, thread uint64_t &hi, thread uint64_t &lo) {
    lo = a * b;
    hi = mulhi(a, b);
}

static inline void fr_mac(uint64_t a, uint64_t b, thread uint64_t &acc, thread uint64_t &carry) {
    uint64_t hi, lo;
    fr_mul64(a, b, hi, lo);
    uint64_t c1 = 0ULL;
    acc = fr_adc(acc, lo, c1);
    uint64_t c2 = 0ULL;
    acc = fr_adc(acc, carry, c2);
    carry = hi + c1 + c2;
}

static inline Fr fr_add(Fr a, Fr b) {
    uint64_t carry = 0;
    Fr r;
    r.limbs[0] = fr_adc(a.limbs[0], b.limbs[0], carry);
    r.limbs[1] = fr_adc(a.limbs[1], b.limbs[1], carry);
    r.limbs[2] = fr_adc(a.limbs[2], b.limbs[2], carry);
    r.limbs[3] = fr_adc(a.limbs[3], b.limbs[3], carry);

    uint64_t borrow = 0;
    Fr s;
    s.limbs[0] = fr_sbb(r.limbs[0], FR_R.limbs[0], borrow);
    s.limbs[1] = fr_sbb(r.limbs[1], FR_R.limbs[1], borrow);
    s.limbs[2] = fr_sbb(r.limbs[2], FR_R.limbs[2], borrow);
    s.limbs[3] = fr_sbb(r.limbs[3], FR_R.limbs[3], borrow);

    if (borrow && !carry) return r;
    return s;
}

static inline Fr fr_sub(Fr a, Fr b) {
    uint64_t borrow = 0;
    Fr r;
    r.limbs[0] = fr_sbb(a.limbs[0], b.limbs[0], borrow);
    r.limbs[1] = fr_sbb(a.limbs[1], b.limbs[1], borrow);
    r.limbs[2] = fr_sbb(a.limbs[2], b.limbs[2], borrow);
    r.limbs[3] = fr_sbb(a.limbs[3], b.limbs[3], borrow);

    if (borrow) {
        uint64_t carry = 0;
        r.limbs[0] = fr_adc(r.limbs[0], FR_R.limbs[0], carry);
        r.limbs[1] = fr_adc(r.limbs[1], FR_R.limbs[1], carry);
        r.limbs[2] = fr_adc(r.limbs[2], FR_R.limbs[2], carry);
        r.limbs[3] = fr_adc(r.limbs[3], FR_R.limbs[3], carry);
    }
    return r;
}

static inline Fr fr_mul(Fr a, Fr b) {
    // 4-limb CIOS Montgomery multiplication
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;

    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        fr_mac(a.limbs[0], b.limbs[i], t0, carry);
        fr_mac(a.limbs[1], b.limbs[i], t1, carry);
        fr_mac(a.limbs[2], b.limbs[i], t2, carry);
        fr_mac(a.limbs[3], b.limbs[i], t3, carry);
        uint64_t c2 = 0;
        t4 = fr_adc(t4, carry, c2);

        // Montgomery reduction step
        uint64_t m_hi, m;
        fr_mul64(t0, FR_INV, m_hi, m);

        carry = 0;
        fr_mac(FR_R.limbs[0], m, t0, carry);
        fr_mac(FR_R.limbs[1], m, t1, carry);
        fr_mac(FR_R.limbs[2], m, t2, carry);
        fr_mac(FR_R.limbs[3], m, t3, carry);
        uint64_t rc_carry = 0;
        t4 = fr_adc(t4, carry, rc_carry);

        // Shift down
        t0 = t1;
        t1 = t2;
        t2 = t3;
        t3 = t4;
        t4 = c2 + rc_carry;
    }

    Fr result = {{t0, t1, t2, t3}};

    // Final conditional subtraction
    uint64_t borrow = 0;
    Fr s;
    s.limbs[0] = fr_sbb(t0, FR_R.limbs[0], borrow);
    s.limbs[1] = fr_sbb(t1, FR_R.limbs[1], borrow);
    s.limbs[2] = fr_sbb(t2, FR_R.limbs[2], borrow);
    s.limbs[3] = fr_sbb(t3, FR_R.limbs[3], borrow);

    if (borrow) return result;
    return s;
}

static inline Fr fr_zero() {
    Fr z = {{0, 0, 0, 0}};
    return z;
}

static inline bool fr_is_zero(Fr a) {
    return (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]) == 0;
}

// Convert from standard representation to Montgomery form: a_mont = a * R^2 * R^(-1) = a * R
static inline Fr fr_to_mont(Fr a) {
    return fr_mul(a, FR_R2);
}
