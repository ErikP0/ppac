pragma solidity >=0.5.0 <0.7.0;

interface SecretStoreACL {
  /**
   * Notifies the contract that the keys of `document` are managed by Secret Store
   * and access to the keys should only provided to those who can craft a
   * zero-knowledge proof that is verifiable with the given verifying key and the
   * public `input`s.
   * NOTE for now, only Groth16 proofs are supported

   * @param  document   bytes32    the 32 byte id of the managed document
   * @param  a          uint256    the point a of a G16 verifying key
   * @param  b          uint256    the point b of a G16 verifying key
   * @param  gamma      uint256    the point gamma of a G16 verifying key
   * @param  delta      uint256    the point delta of a G16 verifying key
   * @param  gamma_abc  uint256[]  the points gamma_abc of a G16 verifying key
   * @param  input      uint[]     the public input of the proof
   */
  function putDocument(bytes32 document, uint256[2] calldata a, uint256[4] calldata b, uint256[4] calldata gamma, uint256[4] calldata delta, uint256[] calldata gamma_abc, uint[] calldata input) external;
  /**
   * This method reverts except if `document` is the id of the joint signing key
   * of the Secret Store.
   *
   * @param  user     address   the user requesting access to `document`
   * @param  document bytes32   the document id `user` is requesting access for
   *
   * @return always true
   */
  function checkPermissions(address user, bytes32 document) external view returns (bool);

  /**
   * This method checks access permissions to the decryption key associated with
   * `document`. `payload`encodes a zero-knowledge proof proving that `user` is
   * authorized by the document's author to access it.
   * NOTE for now, only Groth16 proofs are supported
   *
   * @param  user     address   the address of the user requesting access. A benign
   *                            user choses a random identity for every interaction.
   * @param  document bytes32   the document key id to be accessed
   * @param  payload  uint[]    a flat encoding of a zk-proof
   *
   * @return bool returns true if `user` is allowed to access `document`, false otherwise
   */
  function checkPermissions(address user, bytes32 document, uint[] calldata payload) external view returns (bool);
}
