pragma circom 2.2.2;

template DotProduct4() {
    signal input a[4];
    signal input b[4];
    signal output out;

    signal acc0;
    signal acc1;
    signal acc2;
    signal acc3;

    acc0 <== a[0] * b[0];
    acc1 <== acc0 + a[1] * b[1];
    acc2 <== acc1 + a[2] * b[2];
    acc3 <== acc2 + a[3] * b[3];
    out <== acc3;
}

component main = DotProduct4();
