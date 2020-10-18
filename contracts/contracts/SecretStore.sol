pragma solidity >=0.5.0 <0.7.0;

import {SecretStoreACL} from "./SecretStoreACL.sol";
import {SecretStoreLogger} from "./SecretStoreLogger.sol";
import {Verifier} from "./GenericVerifier.sol";

contract SecretStore is SecretStoreACL, SecretStoreLogger {

  struct Document {
      bool isPresent;
      address owner;
      uint[] input;
      Verifier.VerifyingKey verifyingKey;
  }

  mapping(bytes32 => Document) acl;
  address immutable jointSignatureAccount;
  bytes32 immutable jointSignatureKeyId;
  mapping(bytes32 => bool) accessLog;
  bytes32 hist = bytes32(0x0);

  constructor(address jointSignatureAccount_, bytes32 jointSignatureKeyId_) public {
    jointSignatureAccount = jointSignatureAccount_;
    jointSignatureKeyId = jointSignatureKeyId_;
  }


  function putDocument(bytes32 document, uint256[2] memory a, uint256[4] memory b, uint256[4] memory gamma, uint256[4] memory delta, uint256[] memory gamma_abc, uint[] memory input) override public {

    // if document is already in ACL, then msg.sender must be the owner
    Document storage aclEntry = acl[document];
    require(!aclEntry.isPresent || msg.sender == aclEntry.owner, "Only the owner can grant access");

    if(!aclEntry.isPresent) {
        aclEntry.isPresent = true;
        aclEntry.owner = msg.sender;
    }
    // construct G16 verifying key
    uint256[2][2] memory b2 = [[b[0], b[1]], [b[2], b[3]]];
    uint256[2][2] memory gamma2 = [[gamma[0], gamma[1]], [gamma[2], gamma[3]]];
    uint256[2][2] memory delta2 = [[delta[0], delta[1]], [delta[2], delta[3]]];
    require(gamma_abc.length % 2 == 0, "Invalid G16 verifying key encoding");
    // the input doesn't need to contain 0x1 and the two nonce fields
    require(input.length + 3 + 1 == gamma_abc.length/2, "Invalid G16 verifying key");
    uint256[2][] memory gamma_abc2 = new uint256[2][](gamma_abc.length/2);
    for(uint i=0; i<gamma_abc.length/2; i++) {
      gamma_abc2[i] = [gamma_abc[2*i], gamma_abc[2*i+1]];
    }

    aclEntry.verifyingKey = Verifier.newG16VerifyingKey(a, b2, gamma2, delta2, gamma_abc2);
    aclEntry.input = input;
  }

  function logAccess(address user, bytes32 document, uint[] memory payload) override public {
    // only the joint signature account is allowed to log
    require(msg.sender == jointSignatureAccount, "Expected joint signature account as sender");
    bytes32 logHash = computeLogEntry(user, document, payload);
    require(!accessLog[logHash], "logAccess replay protection");
    accessLog[logHash] = true;
    hist = computeHistHash(document, user);
  }

  function checkPermissions(address /*user*/, bytes32 document) override public view returns (bool) {
    // only allow access to jointSignatureKeyId
    require(document == jointSignatureKeyId, "Use checkPermissions(address,bytes32,uint256[]) for all document access");
    return true;
  }

  function checkPermissions(address user, bytes32 document, uint[] memory payload) override public view returns (bool) {
    bytes32 logHash = computeLogEntry(user, document, payload);
    require(accessLog[logHash], "access has not been logged yet");
    require(payload.length == 8, "Invalid G16 proof encoding");

    Document storage aclEntry = acl[document];
    // document doesn't exist
    if(!aclEntry.isPresent) {
        return false;
    }
    // construct a G16 proof
    uint256[2] memory a = [payload[0], payload[1]];
    uint256[2][2] memory b = [[payload[2], payload[3]], [payload[4], payload[5]]];
    uint256[2] memory c = [payload[6], payload[7]];
    (uint256 nonce_h, uint256 nonce_l) = split(uint256(computeHistHash(document, user)));
    Verifier.Proof memory proof = Verifier.newG16Proof(a,b,c);
    uint256[] memory input = new uint256[](aclEntry.input.length + 3);
    for (uint i=0; i< aclEntry.input.length; i++) {
      input[i] = aclEntry.input[i];
    }
    input[aclEntry.input.length] = nonce_h;
    input[aclEntry.input.length+1] = nonce_l;
    input[aclEntry.input.length+2] = uint(0x1);
    return Verifier.verifyTx(proof, aclEntry.verifyingKey, input);
  }

  function getHist() override public view returns (bytes32) {
    return hist;
  }

  function computeLogEntry(address user, bytes32 document, uint[] memory payload) private pure returns (bytes32) {
    return sha256(abi.encodePacked(user, document, payload));
  }

  function computeHistHash(bytes32 document, address user) private view returns (bytes32) {
    return keccak256(abi.encode(hist, document, user));
  }

  function split(uint256 x) private pure returns (uint256 h, uint256 l) {
      l = uint256(uint128(x));
      h = uint256(uint128(x >> 128));
  }
}
