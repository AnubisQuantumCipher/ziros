// BabyBear field: p = 15 * 2^27 + 1 = 2013265921
// Pure arithmetic helpers — NO kernel functions, NO #include

constant uint32_t BB_P = 2013265921u;
constant uint64_t BB_BARRETT_MU = 9162596893ull;

static inline uint32_t bb_add(uint32_t a, uint32_t b) {
    uint32_t sum = a + b;
    return (sum >= BB_P) ? (sum - BB_P) : sum;
}

static inline uint32_t bb_sub(uint32_t a, uint32_t b) {
    return (a >= b) ? (a - b) : (a + BB_P - b);
}

static inline uint32_t bb_neg(uint32_t a) {
    return (a == 0) ? 0 : (BB_P - a);
}

static inline uint32_t bb_mul(uint32_t a, uint32_t b) {
    uint64_t prod = (uint64_t)a * (uint64_t)b;
    uint64_t q = mulhi(prod, BB_BARRETT_MU);
    uint32_t r = (uint32_t)(prod - q * BB_P);
    return (r >= BB_P) ? (r - BB_P) : r;
}
