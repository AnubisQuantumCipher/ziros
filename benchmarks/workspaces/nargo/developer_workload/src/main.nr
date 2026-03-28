fn main(
    a0: Field,
    a1: Field,
    a2: Field,
    a3: Field,
    b0: Field,
    b1: Field,
    b2: Field,
    b3: Field,
    expected: pub Field,
) {
    let acc = a0 * b0 + a1 * b1 + a2 * b2 + a3 * b3;
    assert(acc == expected);
}
