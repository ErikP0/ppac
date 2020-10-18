const SecretStore = artifacts.require("SecretStore");

contract("SecretStore", accounts => {
  const signatureKeyId = "0x7fdfdba09411e4754f02e57b9c19ad7a3b556d4182147b271e62e635b1aceeff";
  const document1 = "0x1c6636adc33f1a96f62c0db1e1dd689906a1d5d48992267b2efce6bc2696b9e6";
  let signatureAccount = accounts[0];
  let user = "0x5dD42Ade97Df0340AbE64D438793ec50181C2dA2";

  it("estimate gas usage", async () => {
    let contractGas = await SecretStore.new.estimateGas(signatureAccount, signatureKeyId);
    let contract = await SecretStore.new(signatureAccount, signatureKeyId);
    // test put document
    let vk = {
      a : ["0x1936c240636390dc823e3a728e94b208eb53c6756d81da57ec3425e05d43ac10", "0x2d70ff78e8216bf29d58923a686d9738278b8ce2fd822e197c85b09286d15566"],
      b : ["0x2b4daf047abe2e7f0b311118c1b963b63695dc0d769cea78849604434de055bf", "0x29c13ecb6f33dbc4b3b8a02e2e255511ce4c26a8a2f299efcc94caf2de4fce00", "0x1da9020008df7f549751f8a251af3b2dc4a2ad3e0870de54acaedd9fc1b47e17", "0x25ea0d7e2b29de431b86a943db30dbf4d98f68df9ca8a9628d14d1591e817d90"],
      gamma : ["0x011016e22ae045444f50fb80f246ec486c7e02af09132cd38c4fcf484983e4f2", "0x00e83c788c2878d1d5eba3ed49b0d81e4c0487dedc3e4d1c2baab5833785b62f", "0x05eb89e741ed5b5d611cebf92d1ed02cd6f3311089f0d400df7d9ced5a48fd41", "0x132a90a3b0d369ccd66e2a5ba04a935e44d8ad5dca93a76bba592a578130a911"],
      delta : ["0x065f6a3323a2abffd621fc263f348eb914904b68d5897729ae34a6b9d33f0852", "0x0c3b60f59d3bd50328a04c0ff6d979199685d0526f89f6ac29d6174ce24707a2", "0x26e7ebce2b44efef6b6315938e33f0a8ecc82dbad635c9efa681ed85bbb59982", "0x12e0f3721230a0f38f6c9913048d5230fd2615ef3ff7f6ee4b20dfe0bdea1a86"],
      gamma_abc : ["0x13e3995deba4a50690a95a380c45f0b1af90f55958d08c0c9cc62fbe232f2ee9", "0x0f744caab6ebbb0ca38fbb6ebe8d8c2ea321fd833fcbe9e55be34e922adc13b9", "0x08379b6a0c9a2b9ca00222cb6d978c4bb13ebbeb5568694e19ed903336083800", "0x0f7d2001c90d8e3efc1f99052dd09ed205a691f602fd03b8a0203d45ba7b3ed8", "0x19897516ecf5eb45ebe7686ae47fc28fdfc33757142cdeee690d78dfe3436fae", "0x2d2bff06f2241d9eff31b2b753f8c67167dc36e4322e4ef2fbc436e357abf499", "0x0b4a2ff916a0e5123558f0942f47abe5abba81378bb20dd9b559a5249ea0ba56", "0x26467966b36b87491e2aaa3aac41f53c1dec40654697f5421f809c321e495e6a", "0x29b0a65bbaa4ef6e26deff9dac56da1526b29805aaa02619ac5f08c9f8679eb2", "0x162dae5970ae1de288f987955620448293b645e8dfc15fef37f80121fc43fe9f"],
      input : ["0x0000000000000000000000000000000000000000000000000000000000000040"]
    };

    // the proof
    let payload = [
      "0x0b74762676ff6e900946d470483ae53a5eb71abf65df330e9b6e5ed7a16f6ff3",
      "0x1b87e0d5e1589b15a9048ac3d587781d079038af70fd964e7fa5c3a0a26ce11b",
      "0x1d36c2566131935d4c92bcca8bbcb0e2afd021c70aac1de938609015c703ced1",
      "0x03203bf5c01a2702219b5052c781eda377277cd14731649fbbe81deeaed12e58",
      "0x2a59a2bbf482500c5e1c9f96c871d125bdd1102fb71c847ab7f7e60c6da622a0",
      "0x1d3e4b769f730b321523ec2b46a3c817013d20ef7ac674d428a09c0402663dba",
      "0x1b31c90812991ecafb335a7af5f52dc0b37317391f8a240500d49436c6b38c1b",
      "0x0fefe2d333ba845ca7fda4e897268020f614b7202d2c41ce5b972d1084b37231"
    ];

    let putDocumentGas = await contract.putDocument.estimateGas(document1, vk.a, vk.b, vk.gamma, vk.delta, vk.gamma_abc, vk.input);
    await contract.putDocument(document1, vk.a, vk.b, vk.gamma, vk.delta, vk.gamma_abc, vk.input);
    let getHistGas = await contract.getHist.estimateGas();
    await contract.getHist();
    let logAccessGas = await contract.logAccess.estimateGas(user, document1, payload);
    await contract.logAccess(user, document1, payload);
    let checkPermissionsGas = await contract.checkPermissions.estimateGas(user, document1, payload);
    let access = await contract.checkPermissions(user, document1, payload);
    assert.equal(access, true);
    console.log("Gas cost for contract: " + contractGas);
    console.log("Gas cost for putDocument: " + putDocumentGas);
    console.log("Gas cost for getHist " + getHistGas);
    console.log("Gas cost for logAccess " + logAccessGas);
    console.log("Gas cost for checkPermissions " + checkPermissionsGas);
  });
});
