// Goldilocks field: p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001
// Pure arithmetic helpers — NO kernel functions, NO #include

constant uint64_t GL_P = 0xFFFFFFFF00000001ULL;

static inline uint64_t gl_add(uint64_t a, uint64_t b) {
    uint64_t sum = a + b;
    uint64_t over = (sum < a) ? 1ULL : 0ULL;
    uint64_t reduced = sum - GL_P;
    uint64_t under = (reduced > sum) ? 1ULL : 0ULL;
    return (over || !under) ? reduced : sum;
}

static inline uint64_t gl_sub(uint64_t a, uint64_t b) {
    uint64_t diff = a - b;
    uint64_t borrow = (diff > a) ? 1ULL : 0ULL;
    return borrow ? (diff + GL_P) : diff;
}

static inline uint64_t gl_neg(uint64_t a) {
    return (a == 0) ? 0 : (GL_P - a);
}

static inline uint64_t gl_reduce128(uint64_t hi, uint64_t lo) {
    uint64_t hi_lo = hi & 0xFFFFFFFFULL;
    uint64_t hi_hi = hi >> 32;
    uint64_t t = gl_sub(lo, hi);
    t = gl_add(t, hi_lo << 32);
    if (hi_hi > 0) {
        uint64_t corr = (hi_hi << 32) - hi_hi;
        t = gl_add(t, corr);
    }
    return t;
}

static inline uint64_t gl_mul(uint64_t a, uint64_t b) {
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

    uint64_t lo = (p0 & 0xFFFFFFFFULL) | (mid << 32);
    uint64_t hi = p3 + (mid >> 32) + (mid_carry << 32);

    return gl_reduce128(hi, lo);
}
