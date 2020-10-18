pragma solidity >=0.5.0 <0.7.0;

interface SecretStoreLogger {
  /**
   * Persists a logging entry of `user` trying to access `document` providing
   * `payload` as authorization data.
   * @param  user     address the user performing the access attempt
   * @param  document bytes32 the document that is accessed
   * @param  payload  uint[]  the authorization data that is provided
   */
  function logAccess(address user, bytes32 document, uint[] calldata payload) external;

  function getHist() external view returns (bytes32);
}
