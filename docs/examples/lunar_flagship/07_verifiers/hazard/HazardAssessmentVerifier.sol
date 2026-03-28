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

contract HazardAssessmentVerifier {
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
        vk.IC = new Pairing.G1Point[](7);
        vk.IC[0] = Pairing.G1Point(uint256(0x0a6d76e37ae49d6571473be9326d39c6c90d42717fa563e16fd57ae5a8ffdfbd), uint256(0x0b569e8d0e196b2404d736aeeb9b19a0269035248492af8e817b0c38bdf7f9f8));
        vk.IC[1] = Pairing.G1Point(uint256(0x05cf7c7bdc1a584351887b83e020a11017b6edbb99a294c993754ee65a7f588f), uint256(0x019e39623312636e2154bab6113364f868f79f5d7d6dde35ff029184bd5d4ce0));
        vk.IC[2] = Pairing.G1Point(uint256(0x2a632936390ec754d4462d4a8afe06d38c5fee6320594684b4fe6899c3a29d2a), uint256(0x1c259ec85792564269b6c519d48373e1ce5c003e24b4f5d8022fc24c4c01a34c));
        vk.IC[3] = Pairing.G1Point(uint256(0x15889288ac5e1ca305b7dd08a7148ca5796eb11e3cbc0b9f838dbd47dc53d259), uint256(0x26e6512948160b75902da5dc53055876d5ceb0cc8f45a3673e7fa0436e45a666));
        vk.IC[4] = Pairing.G1Point(uint256(0x21e144ad13721a131125baf603cf454e5417f1d99ce9ae2e8fd0b9972ed8243a), uint256(0x0dbce481f71bd9a95c4cabc895d1f60445266c29a5edc2ff4cd697a48d869b3d));
        vk.IC[5] = Pairing.G1Point(uint256(0x0924715759bd83efa3da781121cd36befe446fab8b8f6c1d15b7bb502cd1afd5), uint256(0x0d677700fa8b1425cadf0ea723ab88991c73fcc9d550e67ef054e9d908f1f2d0));
        vk.IC[6] = Pairing.G1Point(uint256(0x0b597fe1757949cbd2a19761cf3ea761c71e126a3ffa8f3bc4954f420c1e70de), uint256(0x0233017563863fed98a8ba74ff0e24083475ba47850fdebf862c48b33f419e8f));
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
