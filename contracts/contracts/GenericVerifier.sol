pragma solidity >=0.5.0 <0.7.0;

import "./generated/BN256G2.sol";
import "./generated/Pairing.sol";

library G16 {
  struct VerifyingKey {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }

    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }

    function verify(uint[] memory input, Proof memory proof, VerifyingKey memory vk) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        require(input.length + 1 == vk.gamma_abc.length, "Invalid input length");
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.a), vk.b)) return 1;
        return 0;
    }
}

library GM17 {
    struct VerifyingKey {
        Pairing.G2Point h;
        Pairing.G1Point g_alpha;
        Pairing.G2Point h_beta;
        Pairing.G1Point g_gamma;
        Pairing.G2Point h_gamma;
        Pairing.G1Point[] query;
    }

    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
}

library PGHR13 {
    struct VerifyingKey {
          Pairing.G2Point a;
          Pairing.G1Point b;
          Pairing.G2Point c;
          Pairing.G2Point gamma;
          Pairing.G1Point gamma_beta_1;
          Pairing.G2Point gamma_beta_2;
          Pairing.G2Point z;
          Pairing.G1Point[] ic;
      }

      struct Proof {
          Pairing.G1Point a;
          Pairing.G1Point a_p;
          Pairing.G2Point b;
          Pairing.G1Point b_p;
          Pairing.G1Point c;
          Pairing.G1Point c_p;
          Pairing.G1Point k;
          Pairing.G1Point h;
      }
}

library Verifier {
    enum ProvingScheme {
        G16, GM17, PGHR13
    }

    struct VerifyingKey {
        ProvingScheme provingScheme;
        uint256[] keyData;
    }

    struct Proof {
        ProvingScheme provingScheme;
        uint256[] proofData;
    }

    function newG16VerifyingKey(G16.VerifyingKey memory verifyingKey) internal pure returns (VerifyingKey memory vk) {
        vk.provingScheme = ProvingScheme.G16;
        vk.keyData = new uint256[](14 + 2*verifyingKey.gamma_abc.length);
        vk.keyData[0] = verifyingKey.a.X;
        vk.keyData[1] = verifyingKey.a.Y;
        vk.keyData[2] = verifyingKey.b.X[0];
        vk.keyData[3] = verifyingKey.b.X[1];
        vk.keyData[4] = verifyingKey.b.Y[0];
        vk.keyData[5] = verifyingKey.b.Y[1];
        vk.keyData[6] = verifyingKey.gamma.X[0];
        vk.keyData[7] = verifyingKey.gamma.X[1];
        vk.keyData[8] = verifyingKey.gamma.Y[0];
        vk.keyData[9] = verifyingKey.gamma.Y[1];
        vk.keyData[10] = verifyingKey.delta.X[0];
        vk.keyData[11] = verifyingKey.delta.X[1];
        vk.keyData[12] = verifyingKey.delta.Y[0];
        vk.keyData[13] = verifyingKey.delta.Y[1];
        for(uint i = 0; i < verifyingKey.gamma_abc.length; i++) {
            vk.keyData[14 + 2*i] = verifyingKey.gamma_abc[i].X;
            vk.keyData[14 + 2*i+1] = verifyingKey.gamma_abc[i].Y;
        }
        return vk;
    }

    function newG16VerifyingKey(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2][2] memory gamma,
        uint256[2][2] memory delta,
        uint256[2][] memory gamma_abc) internal pure returns (VerifyingKey memory vk) {

        vk.provingScheme = ProvingScheme.G16;
        vk.keyData = new uint256[](14 + 2*gamma_abc.length);
        vk.keyData[0] = a[0];
        vk.keyData[1] = a[1];
        vk.keyData[2] = b[0][0];
        vk.keyData[3] = b[0][1];
        vk.keyData[4] = b[1][0];
        vk.keyData[5] = b[1][1];
        vk.keyData[6] = gamma[0][0];
        vk.keyData[7] = gamma[0][1];
        vk.keyData[8] = gamma[1][0];
        vk.keyData[9] = gamma[1][1];
        vk.keyData[10] = delta[0][0];
        vk.keyData[11] = delta[0][1];
        vk.keyData[12] = delta[1][0];
        vk.keyData[13] = delta[1][1];
        for(uint i = 0; i < gamma_abc.length; i++) {
            vk.keyData[14 + 2*i] = gamma_abc[i][0];
            vk.keyData[14 + 2*i+1] = gamma_abc[i][1];
        }
        return vk;
    }

    function newG16Proof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c) internal pure returns (Proof memory p) {

        p.provingScheme = ProvingScheme.G16;
        p.proofData = new uint256[](8);
        p.proofData[0] = a[0];
        p.proofData[1] = a[1];
        p.proofData[2] = b[0][0];
        p.proofData[3] = b[0][1];
        p.proofData[4] = b[1][0];
        p.proofData[5] = b[1][1];
        p.proofData[6] = c[0];
        p.proofData[7] = c[1];
        return p;
    }

    function toG16VerifyingKey(VerifyingKey memory verifyingKey) private pure returns (G16.VerifyingKey memory vk) {
        require(verifyingKey.provingScheme == ProvingScheme.G16, 'Not a G16 VerifyingKey');
        require(verifyingKey.keyData.length >= 14, 'Invalid keyData encoding');
        require(verifyingKey.keyData.length % 2 == 0, 'Invalid keyData encoding');
        vk.a = Pairing.G1Point(verifyingKey.keyData[0], verifyingKey.keyData[1]);
        vk.b = Pairing.G2Point([verifyingKey.keyData[2],verifyingKey.keyData[3]], [verifyingKey.keyData[4],verifyingKey.keyData[5]]);
        vk.gamma = Pairing.G2Point([verifyingKey.keyData[6],verifyingKey.keyData[7]], [verifyingKey.keyData[8], verifyingKey.keyData[9]]);
        vk.delta = Pairing.G2Point([verifyingKey.keyData[10], verifyingKey.keyData[11]], [verifyingKey.keyData[12], verifyingKey.keyData[13]]);
        uint gamma_abc_length = verifyingKey.keyData.length - 14;
        vk.gamma_abc = new Pairing.G1Point[](gamma_abc_length/2);
        for(uint i = 0; i < gamma_abc_length/2; i++) {
            vk.gamma_abc[i] = Pairing.G1Point(verifyingKey.keyData[14+2*i], verifyingKey.keyData[14+2*i+1]);
        }
        return vk;
    }

    function toG16Proof(Proof memory proof) private pure returns (G16.Proof memory p) {
        require(proof.provingScheme == ProvingScheme.G16, 'Not a G16 Proof');
        require(proof.proofData.length == 8, 'Invalid proofData encoding');
        p.a = Pairing.G1Point(proof.proofData[0], proof.proofData[1]);
        p.b = Pairing.G2Point([proof.proofData[2], proof.proofData[3]], [proof.proofData[4], proof.proofData[5]]);
        p.c = Pairing.G1Point(proof.proofData[6], proof.proofData[7]);
        return p;
    }

    function verifyTx(Proof memory proof, VerifyingKey memory verifyingKey, uint[] memory input) internal view returns (bool) {
        require(proof.provingScheme == verifyingKey.provingScheme, 'Proving schemes are not consistent');
        if(proof.provingScheme == ProvingScheme.G16) {
            G16.Proof memory g16Proof = toG16Proof(proof);
            G16.VerifyingKey memory g16Vk = toG16VerifyingKey(verifyingKey);
            return G16.verify(input, g16Proof, g16Vk) == 0;
        }else if(proof.provingScheme == ProvingScheme.GM17) {
            revert('Not yet implemented');
        }else if(proof.provingScheme == ProvingScheme.PGHR13) {
            revert('Not yet implemented');
        }else{
            revert('Unsupported proving scheme');
        }
    }

}
