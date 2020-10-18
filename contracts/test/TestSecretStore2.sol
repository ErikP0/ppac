pragma solidity >=0.5.0 <0.7.0;

import "truffle/Assert.sol";

import "../contracts/SecretStore.sol";
import {UserForTestSecretStore as User} from "../contracts/UserForTestSecretStore.sol";

contract TestSecretStore2 {
  User jointSignatureAccount = new User();
  User alice = new User();
  bytes32 jointSignatureKeyId = 0x7fdfdba09411e4754f02e57b9c19ad7a3b556d4182147b271e62e635b1acee84;
  address bob = 0x5dD42Ade97Df0340AbE64D438793ec50181C2dA2;
  address charly = 0xe5099a3d3297D3781158B4DD7517C0847621aDB0;

  function testCheckPermissionsWithPayloadRevertsOnInvalidEncodedG16Proof1() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    // the flat encoding of a G16 proof is 8 elements
    uint[] memory payload = new uint[](0);

    // do log call
    jointSignatureAccount.logAccess(acl, bob, document, payload);
    // pass less than 8 elements
    (bool noError, ) = address(acl).call(abi.encodeWithSignature("checkPermissions(address,bytes32,uint256[])", bob, document, payload));
    Assert.isFalse(noError, "expected revert due to invalid G16 encoding");
  }

  function testCheckPermissionsWithPayloadRevertsOnInvalidEncodedG16Proof2() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    // the flat encoding of a G16 proof is 8 elements
    uint[] memory payload = new uint[](9);
    for(uint i=0; i<9; i++) {
      payload[i] = uint(i);
    }

    // do log call
    jointSignatureAccount.logAccess(acl, bob, document, payload);
    // pass more than 8 elements
    (bool noError, ) = address(acl).call(abi.encodeWithSignature("checkPermissions(address,bytes32,uint256[])", bob, document, payload));
    Assert.isFalse(noError, "expected revert due to invalid G16 encoding");
  }

  function testCheckPermissionsWithPayload() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;

    {
      uint[2] memory a = [0x1936c240636390dc823e3a728e94b208eb53c6756d81da57ec3425e05d43ac10, 0x2d70ff78e8216bf29d58923a686d9738278b8ce2fd822e197c85b09286d15566];
      uint[4] memory b = [0x2b4daf047abe2e7f0b311118c1b963b63695dc0d769cea78849604434de055bf, 0x29c13ecb6f33dbc4b3b8a02e2e255511ce4c26a8a2f299efcc94caf2de4fce00, 0x1da9020008df7f549751f8a251af3b2dc4a2ad3e0870de54acaedd9fc1b47e17, 0x25ea0d7e2b29de431b86a943db30dbf4d98f68df9ca8a9628d14d1591e817d90];
      uint[4] memory gamma = [0x011016e22ae045444f50fb80f246ec486c7e02af09132cd38c4fcf484983e4f2, 0x00e83c788c2878d1d5eba3ed49b0d81e4c0487dedc3e4d1c2baab5833785b62f, 0x05eb89e741ed5b5d611cebf92d1ed02cd6f3311089f0d400df7d9ced5a48fd41, 0x132a90a3b0d369ccd66e2a5ba04a935e44d8ad5dca93a76bba592a578130a911];
      uint[4] memory delta = [0x065f6a3323a2abffd621fc263f348eb914904b68d5897729ae34a6b9d33f0852, 0x0c3b60f59d3bd50328a04c0ff6d979199685d0526f89f6ac29d6174ce24707a2, 0x26e7ebce2b44efef6b6315938e33f0a8ecc82dbad635c9efa681ed85bbb59982, 0x12e0f3721230a0f38f6c9913048d5230fd2615ef3ff7f6ee4b20dfe0bdea1a86];
      uint[] memory gamma_abc = new uint[](10);
      gamma_abc[0] = 0x13e3995deba4a50690a95a380c45f0b1af90f55958d08c0c9cc62fbe232f2ee9;
      gamma_abc[1] = 0x0f744caab6ebbb0ca38fbb6ebe8d8c2ea321fd833fcbe9e55be34e922adc13b9;
      gamma_abc[2] = 0x08379b6a0c9a2b9ca00222cb6d978c4bb13ebbeb5568694e19ed903336083800;
      gamma_abc[3] = 0x0f7d2001c90d8e3efc1f99052dd09ed205a691f602fd03b8a0203d45ba7b3ed8;
      gamma_abc[4] = 0x19897516ecf5eb45ebe7686ae47fc28fdfc33757142cdeee690d78dfe3436fae;
      gamma_abc[5] = 0x2d2bff06f2241d9eff31b2b753f8c67167dc36e4322e4ef2fbc436e357abf499;
      gamma_abc[6] = 0x0b4a2ff916a0e5123558f0942f47abe5abba81378bb20dd9b559a5249ea0ba56;
      gamma_abc[7] = 0x26467966b36b87491e2aaa3aac41f53c1dec40654697f5421f809c321e495e6a;
      gamma_abc[8] = 0x29b0a65bbaa4ef6e26deff9dac56da1526b29805aaa02619ac5f08c9f8679eb2;
      gamma_abc[9] = 0x162dae5970ae1de288f987955620448293b645e8dfc15fef37f80121fc43fe9f;
      uint[] memory input = new uint[](1);
      // public input 64
      input[0] = 0x0000000000000000000000000000000000000000000000000000000000000040;
      alice.putDocument(acl, document, a, b, gamma, delta, gamma_abc, input);
    }

    {
      // first nonce: 3d48c5d24860574a4d2e947e51e1786e4b9505144386a1b00bc1ed0131791dac
      // higher: 81460765411699813013295304988243884142
      // lower: 100465854933299903594411842775249657260

      // constuct a valid proof & access document
      uint[] memory payload = new uint[](8);
      // a
      payload[0] = 0x0b74762676ff6e900946d470483ae53a5eb71abf65df330e9b6e5ed7a16f6ff3;
      payload[1] = 0x1b87e0d5e1589b15a9048ac3d587781d079038af70fd964e7fa5c3a0a26ce11b;
      // b
      payload[2] = 0x1d36c2566131935d4c92bcca8bbcb0e2afd021c70aac1de938609015c703ced1;
      payload[3] = 0x03203bf5c01a2702219b5052c781eda377277cd14731649fbbe81deeaed12e58;
      payload[4] = 0x2a59a2bbf482500c5e1c9f96c871d125bdd1102fb71c847ab7f7e60c6da622a0;
      payload[5] = 0x1d3e4b769f730b321523ec2b46a3c817013d20ef7ac674d428a09c0402663dba;
      // c
      payload[6] = 0x1b31c90812991ecafb335a7af5f52dc0b37317391f8a240500d49436c6b38c1b;
      payload[7] = 0x0fefe2d333ba845ca7fda4e897268020f614b7202d2c41ce5b972d1084b37231;

      Assert.equal(acl.getHist(), bytes32(0), "history is 0");
      // do log call
      jointSignatureAccount.logAccess(acl, bob, document, payload);
      Assert.equal(acl.getHist(), bytes32(0xa4820e4a8a9e1adf0e38fe02036154473e1bf1d81ea16f4666ca7d2c886ed597), "history1");

      Assert.isTrue(acl.checkPermissions(bob, document, payload), "expected true for correct proof");
    }

    {
      // second nonce: 0x2175aa193ef84f06a31d5162eeed3702ea0d8269c05301d5e15aa40dabb9ca19
      // higher: 44475472603175739680518285459444283138
      // lower: 311109495964558277130060018794161097241
      // constuct an invalid proof & access document
      uint[] memory payload = new uint[](8);
      // a
      payload[0] = 0x16109385e3a96c686f299d3caac96482b26b6f6bbab438fdc02c654757e1d167;
      payload[1] = 0x218a362d858869040442184ff0f5d92ba6dda0792198041917fceb10d04f494f;
      // b
      payload[2] = 0x21fe59208165be4b0524a6c4f7b87464b42851ff6c259dd95a96574c4cc8ec73;
      payload[3] = 0x179336d54e93cae5f5c38b87ab9424217706245642f374445fae4e99d51c1b1a;
      payload[4] = 0x276a23f376ad06f13086ad23b0678485a6ae627ae959ef23d2ff1907dad53099;
      payload[5] = 0x0c54085d6d8ddb84a6e50aa7d713b955ac8d28e4f17ffd54ced807aed300749b;
      // c
      payload[6] = 0x16109385e3a96c686f299d3caac96482b26b6f6bbab438fdc02c654757e1d167;
      payload[7] = 0x218a362d858869040442184ff0f5d92ba6dda0792198041917fceb10d04f494f;

      // do log call
      jointSignatureAccount.logAccess(acl, bob, document, payload);

      Assert.isFalse(acl.checkPermissions(bob, document, payload), "expected false for incorrect proof");
    }
  }
}
