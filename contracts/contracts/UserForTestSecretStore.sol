pragma solidity >=0.5.0 <0.7.0;

import "./SecretStore.sol";

contract UserForTestSecretStore {

  function putDocument(SecretStore store, bytes32 document, uint256[2] memory a, uint256[4] memory b, uint256[4] memory gamma, uint256[4] memory delta, uint256[] memory gamma_abc, uint[] memory input) public {
    store.putDocument(document, a, b, gamma, delta, gamma_abc, input);
  }

  function logAccess(SecretStore store, address user, bytes32 document, uint[] memory payload) public {
    store.logAccess(user, document, payload);
  }

  function checkPermissions(SecretStore store, address user, bytes32 document) public view returns (bool) {
    return store.checkPermissions(user, document);
  }

  function checkPermissions(SecretStore store, address user, bytes32 document, uint[] memory payload) public view returns (bool) {
    return store.checkPermissions(user, document, payload);
  }
}
