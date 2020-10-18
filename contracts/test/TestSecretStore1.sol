pragma solidity >=0.5.0 <0.7.0;

import "truffle/Assert.sol";

import "../contracts/SecretStore.sol";
import {UserForTestSecretStore as User} from "../contracts/UserForTestSecretStore.sol";

contract TestSecretStore1 {
  User jointSignatureAccount = new User();
  User alice = new User();
  bytes32 jointSignatureKeyId = 0x7fdfdba09411e4754f02e57b9c19ad7a3b556d4182147b271e62e635b1acee84;
  address bob = 0x5dD42Ade97Df0340AbE64D438793ec50181C2dA2;
  address charly = 0xe5099a3d3297D3781158B4DD7517C0847621aDB0;

  function testLogAccess() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);

    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    uint[] memory payload = new uint256[](3);
    payload[0] = uint(0x1);
    payload[1] = uint(0x2);
    payload[2] = uint(0x3);
    // only the jointSignatureAccount can call logAccess
    jointSignatureAccount.logAccess(acl, bob, document, payload);
  }

  function testLogAccessReverts() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);

    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    uint[] memory payload = new uint256[](3);
    payload[0] = uint(0x1);
    payload[1] = uint(0x2);
    payload[2] = uint(0x3);
    // only the jointSignatureAccount can call logAccess
    (bool noError,) = address(acl).call(abi.encodeWithSignature("logAccess(address,bytes32,uint256[])", bob, document, payload));
    // expect revert
    Assert.isFalse(noError, "logAccess called from account different from jointSignatureAccount");
  }

  function testPutDocumentRevertsIfNonOwnerAttemptsChange() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    uint[2] memory a = [uint(0x0), uint(0x0)];
    uint[4] memory b = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    uint[4] memory gamma = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    uint[4] memory delta = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    uint[] memory gamma_abc = new uint[](10);
    gamma_abc[0] = uint(0x0);
    gamma_abc[1] = uint(0x0);
    gamma_abc[2] = uint(0x0);
    gamma_abc[3] = uint(0x0);
    gamma_abc[4] = uint(0x0);
    gamma_abc[5] = uint(0x0);
    gamma_abc[6] = uint(0x0);
    gamma_abc[7] = uint(0x0);
    gamma_abc[8] = uint(0x0);
    gamma_abc[9] = uint(0x0);
    uint[] memory input = new uint[](1);
    input[0] = uint(0x0);
    // store a document with user alice
    {
      (bool noError,) = address(alice).call(abi.encodeWithSignature("putDocument(address,bytes32,uint256[2],uint256[4],uint256[4],uint256[4],uint256[],uint256[])", address(acl), document, a, b, gamma, delta, gamma_abc, input));
      Assert.isTrue(noError, "upload of unknown document should not revert");
    }

    // now try to change it from a different user
    (bool noError,) = address(acl).call(abi.encodeWithSignature("putDocument(bytes32,uint256[2],uint256[4],uint256[4],uint256[4],uint256[],uint256[])", document, a, b, gamma, delta, gamma_abc, input));
    Assert.isFalse(noError, "non owner attempted changing access policy on document");
  }

  function testPutDocumentRevertsOnInvalidEncodedG16VerifyingKey1() public {
    // flat encoding of G16 VK's gamma_abc
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    uint[2] memory a = [uint(0x0), uint(0x0)];
    uint[4] memory b = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    uint[4] memory gamma = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    uint[4] memory delta = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    // a odd gamma_abc can never be a list of G1 points
    uint[] memory gamma_abc = new uint[](3);
    gamma_abc[0] = uint(0x0);
    gamma_abc[1] = uint(0x0);
    gamma_abc[2] = uint(0x0);
    uint[] memory input = new uint[](1);
    input[0] = uint(0x1);
    // expect revert
    (bool noError,) = address(acl).call(abi.encodeWithSignature("putDocument(bytes32,uint256[2],uint256[4],uint256[4],uint256[4],uint256[],uint256[])", document, a, b, gamma, delta, gamma_abc, input));
    Assert.isFalse(noError, "supplied invalid gamma_abc encoding");
  }

  function testPutDocumentRevertsOnInvalidEncodedG16VerifyingKey2() public {
    // invalid input length
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    uint[2] memory a = [uint(0x0), uint(0x0)];
    uint[4] memory b = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    uint[4] memory gamma = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    uint[4] memory delta = [uint(0x0), uint(0x0), uint(0x0), uint(0x0)];
    // gamma_abc encodes 3 points
    uint[] memory gamma_abc = new uint[](6);
    gamma_abc[0] = uint(0x0);
    gamma_abc[1] = uint(0x0);
    gamma_abc[2] = uint(0x0);
    gamma_abc[3] = uint(0x0);
    gamma_abc[4] = uint(0x0);
    gamma_abc[5] = uint(0x0);
    // VK's gamma_abc contains one point more than public inputs
    // only provide 1 input
    uint[] memory input = new uint[](1);
    input[0] = uint(0x1);
    // expect revert
    (bool noError,) = address(acl).call(abi.encodeWithSignature("putDocument(bytes32,uint256[2],uint256[4],uint256[4],uint256[4],uint256[],uint256[])", document, a, b, gamma, delta, gamma_abc, input));
    Assert.isFalse(noError, "supplied invalid input length");
  }

  function testcheckPermissionsReturnsTrueForSignatureKeyId() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    Assert.isTrue(acl.checkPermissions(bob, jointSignatureKeyId), "expected true for jointSignatureKeyId");
  }

  function testcheckPermissionsRevertsOtherwise() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    // reverts for different key
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    (bool noError,) = address(acl).call(abi.encodeWithSignature("checkPermissions(address,bytes32)", bob, document));
    Assert.isFalse(noError, "checkPermissions(address,bytes32) reverts for every key id except jointSignatureKeyId");
  }

  function testCheckPermissionsWithPayloadRevertsIfNotLogged() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    uint[] memory payload = new uint[](0);

    // reverts as logAccess has not been called
    (bool noError,) = address(acl).call(abi.encodeWithSignature("checkPermissions(address,bytes32,uint256[])", bob, document, payload));
    Assert.isFalse(noError, "checkPermissionsWithPayload reverts if log has not been called");
  }

  function testCheckPermissionsWithPayloadReturnsFalseForUnknownDocument() public {
    SecretStore acl = new SecretStore(address(jointSignatureAccount), jointSignatureKeyId);
    bytes32 document = 0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6;
    // the flat encoding of a G16 proof is 8 elements
    uint[] memory payload = new uint[](8);
    for(uint i=0; i<8; i++) {
      payload[i] = uint(i);
    }

    // do log call
    jointSignatureAccount.logAccess(acl, bob, document, payload);
    Assert.isFalse(acl.checkPermissions(bob, document, payload), "returns false for unknown document");
  }
}
