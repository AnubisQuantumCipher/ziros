// Batch multi-column NTT butterfly kernels
// Processes multiple NTT columns in a single GPU dispatch using 2D grids.
// Field arithmetic helpers are included before this file via concatenation.
//
// Buffer layout: all columns packed contiguously with stride.
// data[row * stride + col] = element at (row, col)

// Goldilocks batch butterfly: 2D dispatch (X=butterfly index, Y=column index)
kernel void ntt_butterfly_goldilocks_batch(
    device uint64_t *data [[buffer(0)]],
    device const uint64_t *twiddles [[buffer(1)]],
    constant uint32_t &stage [[buffer(2)]],
    constant uint32_t &n [[buffer(3)]],        // height (NTT size per column)
    constant uint32_t &stride [[buffer(4)]],   // number of columns (width)
    uint2 tid [[thread_position_in_grid]])
{
    uint32_t butterfly_id = tid.x;
    uint32_t col = tid.y;

    if (col >= stride) return;

    uint32_t half_n = 1u << stage;
    uint32_t group_size = half_n << 1;
    uint32_t group = butterfly_id / half_n;
    uint32_t pos = butterfly_id % half_n;

    uint32_t idx0 = group * group_size + pos;
    uint32_t idx1 = idx0 + half_n;

    if (idx1 >= n) return;

    // data is in row-major order: data[row * stride + col]
    uint32_t offset0 = idx0 * stride + col;
    uint32_t offset1 = idx1 * stride + col;

    uint64_t a = data[offset0];
    uint64_t b = data[offset1];
    uint64_t w = twiddles[half_n + pos];

    uint64_t wb = gl_mul(w, b);
    data[offset0] = gl_add(a, wb);
    data[offset1] = gl_sub(a, wb);
}

// BabyBear batch butterfly: 2D dispatch (X=butterfly index, Y=column index)
kernel void ntt_butterfly_babybear_batch(
    device uint32_t *data [[buffer(0)]],
    device const uint32_t *twiddles [[buffer(1)]],
    constant uint32_t &stage [[buffer(2)]],
    constant uint32_t &n [[buffer(3)]],
    constant uint32_t &stride [[buffer(4)]],
    uint2 tid [[thread_position_in_grid]])
{
    uint32_t butterfly_id = tid.x;
    uint32_t col = tid.y;

    if (col >= stride) return;

    uint32_t half_n = 1u << stage;
    uint32_t group_size = half_n << 1;
    uint32_t group = butterfly_id / half_n;
    uint32_t pos = butterfly_id % half_n;

    uint32_t idx0 = group * group_size + pos;
    uint32_t idx1 = idx0 + half_n;

    if (idx1 >= n) return;

    uint32_t offset0 = idx0 * stride + col;
    uint32_t offset1 = idx1 * stride + col;

    uint32_t a = data[offset0];
    uint32_t b = data[offset1];
    uint32_t w = twiddles[half_n + pos];

    uint32_t wb = bb_mul(w, b);
    data[offset0] = bb_add(a, wb);
    data[offset1] = bb_sub(a, wb);
}
