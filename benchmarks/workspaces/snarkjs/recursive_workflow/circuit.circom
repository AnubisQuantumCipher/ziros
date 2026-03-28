pragma circom 2.2.2;

template Fibonacci8() {
    signal input seed0;
    signal input seed1;
    signal output out;

    signal f2;
    signal f3;
    signal f4;
    signal f5;
    signal f6;
    signal f7;
    signal f8;
    signal f9;

    f2 <== seed0 + seed1;
    f3 <== seed1 + f2;
    f4 <== f2 + f3;
    f5 <== f3 + f4;
    f6 <== f4 + f5;
    f7 <== f5 + f6;
    f8 <== f6 + f7;
    f9 <== f7 + f8;

    out <== f9;
}

component main = Fibonacci8();
