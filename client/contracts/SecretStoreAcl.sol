pragma solidity >=0.5.0 <0.7.0;

interface SecretStoreAcl {
  function putDocument(bytes32 document,
      uint256[2] memory a,
      uint256[4] memory b,
      uint256[4] memory gamma,
      uint256[4] memory delta,
      uint256[] memory gamma_abc,
      uint[] memory input) external;
  
  function getHist() external view returns (bytes32);
}
