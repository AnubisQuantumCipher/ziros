// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

library Pairing {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory r) {
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            switch success case 0 { invalid() }
        }
        require(success, "pairing-add-failed");
    }

    function scalarMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success case 0 { invalid() }
        }
        require(success, "pairing-mul-failed");
    }

    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length, "pairing-lengths-failed");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            switch success case 0 { invalid() }
        }
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }

    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1; p2[0] = a2;
        p1[1] = b1; p2[1] = b2;
        p1[2] = c1; p2[2] = c2;
        p1[3] = d1; p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract PoweredDescentVerifier {
    using Pairing for *;

    struct VerifyingKey {
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alpha1 = Pairing.G1Point(uint256(0x2a29a5da108739dc61c032f8ee0ea1b47d221cbad95a02c78f11ffd5cba9c37b), uint256(0x0741eb6c6f4a450813962e3b2108f5e0bb36f52e1ba1b5101950b1f39bffae6d));
        vk.beta2 = Pairing.G2Point([uint256(0x06d8380df00bdef44bddc451a997d5fb423239bab37cb76dae7717237ed5761c), uint256(0x225ae2b3583e3a450b30423555183f9a23042f02411886c607e3e5dd1e5c7121)], [uint256(0x2bff412b422e9b9a717be0d6289726f1eccc5b4727017b6da075436ba1a5e9e4), uint256(0x0de8d468bdfc38e9732b8c79e3b4ef767184cd2cf4649493459a58f8fea08e12)]);
        vk.gamma2 = Pairing.G2Point([uint256(0x0c6ec37f3263f3f2739f0a8d2c49957938bb7642b19246ce4991906c1928df5d), uint256(0x1dea8ea8483c133b75d0f89faf4fe5eac66fa2ad9a8eb6af94ec7d288d71f05c)], [uint256(0x0f0034db2bd2f984e0749c99ba11e5edd0fba9c999ae8a5d3f7a5f45505b3b30), uint256(0x1090da9b79241447f1ff51f63158f913eca99036439d9fa8c5cf34e4dd4bdf71)]);
        vk.delta2 = Pairing.G2Point([uint256(0x14568c41c03fc7821078962971bba9da3156a5177331b9bfa18cd2694f6ba548), uint256(0x0c7d5bef2ccaffb9cdcb2717e5c3b27ac1c4299ddaf9376cdeba11f0ca0292e9)], [uint256(0x21a1cf8da9c9343758c2e0ade5bd51578c71f7b452589bddbaa6cbb68fbfa16b), uint256(0x24991212b6bcce1beedb4780f1c135ab75ec99cef4e8160d189ccae42e4afefa)]);
        vk.IC = new Pairing.G1Point[](14);
        vk.IC[0] = Pairing.G1Point(uint256(0x23f7670af7fa92988e20d81684004df63e257aec66f9659f173824a9395b6080), uint256(0x1d522988156b63425c61e5974585b6abda660933da002f7bd355073a05850d2c));
        vk.IC[1] = Pairing.G1Point(uint256(0x0ba858a9d303a197a0cb39009258d3ac92e96561915287b922a336d9b625e506), uint256(0x1253ee31c5567d8388488e4f9928a212abe1f2b775e2e264556e7197c44cac09));
        vk.IC[2] = Pairing.G1Point(uint256(0x2a7447c9d9ff6aafd5649cc4eee8e6067206ca24399fa10cef6f52faba6e2984), uint256(0x0a9859f3d04c489fe9a8059c3ef8d9046d513229964248dcb7553e089fa0b504));
        vk.IC[3] = Pairing.G1Point(uint256(0x1a844ded04eed5327e792644525c0a0de7190fcd99c4dfa2fc8ef59719ee4b9d), uint256(0x095c02027173f7ef5434fa75240bb46076e7d0c205b0dd5ae0120f30e6984af1));
        vk.IC[4] = Pairing.G1Point(uint256(0x23105f274fe4a1eaa4df3a3fdce2d00738b0a21367d64edebeef9ade222bdc3e), uint256(0x26abf36678b029dec49f5d0d5569d58ac1cb5cd768a8c73a33a6b06a7e0a227d));
        vk.IC[5] = Pairing.G1Point(uint256(0x11a87d7fa06ef7a42891166139b292cb59a70a2780e04964a391efac6f61f598), uint256(0x14b39aa2034b7e0bf82647ca36a189cec3c18e12b5266e2a31f68e896b579605));
        vk.IC[6] = Pairing.G1Point(uint256(0x260736c7aa08663eaba8c0d4b17b46318b27585f7c118919e35883996041a564), uint256(0x14414dcb74e05e53bb5d41c9fe9f916c7e0936157c548b323da97f758881ec2a));
        vk.IC[7] = Pairing.G1Point(uint256(0x024a4cc06c6c7b31d00332bb7e629e0a9a6df77e7897caf2d7e1f2ef3dea69ed), uint256(0x02b600747e00192cf94dbc56cfe4bd34d48573dd0f0add8768385ff275e689cd));
        vk.IC[8] = Pairing.G1Point(uint256(0x227d2ecb19bd8bf560b88568b455754c7c3dbbe5493cfc22fbdedc0f4b267f7a), uint256(0x2b5fcfa7497c0af40247a5e94f5b2594d8f63d53e9e5cc0adc342d94ec1abd6e));
        vk.IC[9] = Pairing.G1Point(uint256(0x2aee95b11c161d583647b74f91ecd5bffba2577761e9a83d7b79e348c46b97a3), uint256(0x1368b28628d9ab247958309569e454da2dc4b2d0b1e0a99f231db1bd8ce08893));
        vk.IC[10] = Pairing.G1Point(uint256(0x1cb6108b6190149a3d58c4876c680490bea403064b09dd31693ca93293ea49e1), uint256(0x00b461bab3ada0a7f014c7f2704e538b78720c54d74e5dafe31dc1c57d4218ce));
        vk.IC[11] = Pairing.G1Point(uint256(0x13731591c702dfd928b1558e77619a712e3defe35b6abb888d7ae076c93fa26c), uint256(0x0bd0d5ae3c46284ab659155a2989e7ce2aeea68cdefa0ddba058b5ca2882798d));
        vk.IC[12] = Pairing.G1Point(uint256(0x184419fc843b18055ffb0f31d4c44042dc360dd27089086a1b399791e1dd7ade), uint256(0x2ffdeb9eddc6df594324f41ce1119ac35f2a6ad34dbc510a7f395d35afd5ae2e));
        vk.IC[13] = Pairing.G1Point(uint256(0x10cf1641bd437ff99a2b06276ef5681079b90c77c4f59fa57f59a26b15f91fe9), uint256(0x23adbf356dc2a04c2828581c40ab1bedfb881889adfc4a4ee21d8813a5826633));
    }

    function verify(uint[] memory input, Proof memory proof) internal view returns (bool) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length, "verifier-bad-input");
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field, "verifier-gte-snark-scalar-field");
            vk_x = Pairing.addition(vk_x, Pairing.scalarMul(vk.IC[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        if (!Pairing.pairingProd4(
            Pairing.negate(proof.A), proof.B,
            vk.alpha1, vk.beta2,
            vk_x, vk.gamma2,
            proof.C, vk.delta2
        )) return false;
        return true;
    }

    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory input
    ) public view returns (bool r) {
        Proof memory proof = Proof({
            A: Pairing.G1Point(a[0], a[1]),
            B: Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]),
            C: Pairing.G1Point(c[0], c[1])
        });
        return verify(input, proof);
    }
}
