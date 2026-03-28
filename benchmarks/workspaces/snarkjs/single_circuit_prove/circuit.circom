pragma circom 2.2.2;

template Multiply() {
    signal input a;
    signal input b;
    signal output out;

    out <== a * b;
}

component main = Multiply();
