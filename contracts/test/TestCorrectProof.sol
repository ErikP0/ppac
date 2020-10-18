pragma solidity >=0.5.0 <0.7.0;

import "truffle/Assert.sol";

import {Verifier} from "../contracts/GenericVerifier.sol";



contract TestCorrectProof {

    uint[2] hash1 = [237410164007148657034170337782177595029,5306082028629740322778830590755376038];
    uint[2] hash2 = [226357019966013324371018536730905827047,111260942291723233661882850381686076961];

    address address1 = 0xE7f34ADa4505B3F72c1a41dD061aF299a7246241; //0x...;
    bytes32 document = 0x7fdfdba09411e4754f02e57b9c19ad7a3b556d4182147b271e62e635b1acee84;

    function validProofForHash1AndAddress1() private pure returns (Verifier.Proof memory p) {
        uint[2] memory a = [0x0486cc86b88ddee308e2c9d0e6f92a0ed9aa95b54fb1c8808116e64380b73ef3, 0x17e4ef9e086368fe6e9b85f0a594a3ca799f5799b1333f4a05e657e7519a5299];
        uint[2][2] memory b = [[0x21f79b437bdcea18d48b9733afcc196d26dbe5a5ded1d6625cda998e85cd076c, 0x19dbed328e426f90432a91c90fbc7da3947b901e3d3323489f5dbf7911ebd70c], [0x25a58cbc49e467a55cf62fb1c98fca068ff309fcec1046b6ba1a1292eea09f41, 0x2fe050bf5002df95bdb43065f5a37dac183323193516459d5ba094f9997d6bac]];
        uint[2] memory c = [0x1fdfc293376d8008c51f23874a7576fa30a588447d29f9630d9d5d1cacda7846, 0x1fa842e2ac4f1d9ff08b74ffbc8d01e435acac8accea6b39de943c0766c446e4];
        p = Verifier.newG16Proof(a,b,c);
    }

    function split(uint256 x) private pure returns (uint256 h, uint256 l) {
        l = uint256(uint128(x));
        h = uint256(uint128(x >> 128));
    }

    // for preimage-with-binding.zok
    function verifyingKey1() private pure returns (Verifier.VerifyingKey memory vk) {
        uint256[2] memory a = [
          uint256(0x1936c240636390dc823e3a728e94b208eb53c6756d81da57ec3425e05d43ac10),
          uint256(0x2d70ff78e8216bf29d58923a686d9738278b8ce2fd822e197c85b09286d15566)
        ];
        uint256[2][2] memory b = [
          [
            uint256(0x2b4daf047abe2e7f0b311118c1b963b63695dc0d769cea78849604434de055bf),
            uint256(0x29c13ecb6f33dbc4b3b8a02e2e255511ce4c26a8a2f299efcc94caf2de4fce00)
          ],
          [
            uint256(0x1da9020008df7f549751f8a251af3b2dc4a2ad3e0870de54acaedd9fc1b47e17),
            uint256(0x25ea0d7e2b29de431b86a943db30dbf4d98f68df9ca8a9628d14d1591e817d90)
          ]
        ];
        uint256[2][2] memory gamma = [
          [
            uint256(0x011016e22ae045444f50fb80f246ec486c7e02af09132cd38c4fcf484983e4f2),
            uint256(0x00e83c788c2878d1d5eba3ed49b0d81e4c0487dedc3e4d1c2baab5833785b62f)
          ],
          [
            uint256(0x05eb89e741ed5b5d611cebf92d1ed02cd6f3311089f0d400df7d9ced5a48fd41),
            uint256(0x132a90a3b0d369ccd66e2a5ba04a935e44d8ad5dca93a76bba592a578130a911)
          ]
        ];
        uint256[2][2] memory delta = [
          [
            uint256(0x065f6a3323a2abffd621fc263f348eb914904b68d5897729ae34a6b9d33f0852),
            uint256(0x0c3b60f59d3bd50328a04c0ff6d979199685d0526f89f6ac29d6174ce24707a2)
          ],
          [
            uint256(0x26e7ebce2b44efef6b6315938e33f0a8ecc82dbad635c9efa681ed85bbb59982),
            uint256(0x12e0f3721230a0f38f6c9913048d5230fd2615ef3ff7f6ee4b20dfe0bdea1a86)
          ]
        ];
        uint256[2][] memory gamma_abc = new uint256[2][](7);
        gamma_abc[0] = [uint256(0x2ec459f3a7fb800b58015ef8d5b1fd9877538590d6b52e42a2d8d17b3108c24f), uint256(0x0540e19ce06c012b812cc151a74dc401a40fb9926e9492acf6561fde4e875ad2)];
        gamma_abc[1] = [uint256(0x1cd1bdbf98a6d5daebd5370917cecb314b7cc6454dcf8bb8c82df3f1237f150b), uint256(0x0502f8dc11a4203499a55474c571e7c6b2b901795e7f3a41cddb76e091b0d7e2)];
        gamma_abc[2] = [uint256(0x0379b049451cf894cd9ac7af863ae025e2192421417294a7baac32ff3d9a2551), uint256(0x17b60833f5a9bd0ed90e73f9b532f3b3a6f185d8c64a130866549ecfe9755ecf)];
        gamma_abc[3] = [uint256(0x1e626b00c1c556a51f767721bf8fbf18b899f3939d524ac80c0900c57bbc9534), uint256(0x002b8d355e056d72bd65f888d8e3b89aa94bc2b7f04a47e87c104e55fa2085ab)];
        gamma_abc[4] = [uint256(0x1cb82b5abd9fc00db1c5b93f0f6c39417e55dc58d766a9825c67e098623ec64d), uint256(0x1034af81f4aa6147819988a85eb8a91b2360a642d6781f7c8915c818333a36c9)];
        gamma_abc[5] = [uint256(0x02ce295338b839d1544de8c45fa5efece20be96e4ad03aa394362cf5792f37d1), uint256(0x1c62dc82d98fcb05f28149dc7ed5e1f6bdcbb10f8c8ca03e80d7234c24b9bb47)];
        gamma_abc[6] = [uint256(0x15df6f0457909a8fd0e19d9eaa2bb3e1c2e349a17a5e9eff1c34059296a58e30), uint256(0x240923c7f3c100f349027a17e7a1ad7b487eda154e56f254642c8c606c1702c5)];
        vk = Verifier.newG16VerifyingKey(a,b,gamma,delta,gamma_abc);
    }

    function test() public {
      (uint document_h, uint document_l) = split(uint256(document));
      uint[] memory input = new uint[](6);
      input[0] = uint256(address1);
      input[1] = document_h;
      input[2] = document_l;
      input[3] = hash1[0];
      input[4] = hash1[1];
      input[5] = uint256(0x1);

      Verifier.VerifyingKey memory vk = verifyingKey1();
      Verifier.Proof memory p = validProofForHash1AndAddress1();
      Assert.isTrue(Verifier.verifyTx(p, vk, input), "Invalid proof");
    }
}
