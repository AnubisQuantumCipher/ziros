fn main(a: Field, b: Field, c: pub Field) {
    // Prove we know a Pythagorean triple (a, b) for a given hypotenuse c
    assert(a * a + b * b == c * c);
    
    // Ensure they are non-zero to avoid trivial 0^2 + 0^2 = 0^2
    assert(a != 0);
    assert(b != 0);
}