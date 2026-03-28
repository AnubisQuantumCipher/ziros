fn main(seed0: Field, seed1: Field, expected: pub Field) {
    let mut a = seed0;
    let mut b = seed1;

    for _i in 0..8 {
        let next = a + b;
        a = b;
        b = next;
    }

    assert(b == expected);
}
