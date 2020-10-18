### Setup

This demo uses `docker` and `docker-compose`. The following entities are simulated via separate containers.

 - 2 containers `chain1` and `chain2` form the active part of the blockchain (PDP nodes)
 - 5 containers `s1-5` are the PEP nodes. Note that those also replicate the blockchain passively.

The jointly generated signature key is stored under document id `0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`
and has a public key `0x64badc4ad6f241882df2e830b9f7ebcd508df4dfa804daa0505fd43023bb3a4626fea404f13b8aa19cf9c05a0432db782c44dd6e5bb2b7483ce75ba3492d5533`
(thus address: `0x7d547faa5f5dcc6ca5eecb1e44137718450fbf27`)

A contract is already deployed at address: `0x6ab58b97a66CE2587D6fFDE1Bc72B78745FF8960`.

### Demo

Start all instances via `docker-compose up`.

#### Alice (document author)

Log into Alice `docker-compose exec alice bash`

1. Create a policy
```
root@alice:/usr/app# ./client -c share/alice-config.json create-policy --circuit share/preimage.zok --threshold 3 --zok-stdlib share/stdlib/ 6441948221896607572742608488120559578 146139290966201238425928859098213699460
```
This uses the pre-made policy that requires knowledge of a preimage of a hash function to fulfill. Here is a valid pair
 - preimage: `1 2 3 4` (4x128 bit encoded seperately)
 - image: `6441948221896607572742608488120559578 146139290966201238425928859098213699460` (2x128 bit encoded seperately)
2. Create a document
```
root@alice:/usr/app# echo "Alice's document" > document
```
3. Upload the document
```
root@alice:/usr/app# ./client -c share/alice-config.json upload --document document  --encrypted-document encrypted --policy policy.json
Successfully uploaded document e538de4cf985ee2da48c49305c1ebb01b16f10adb527689b8a0be4c0178e79c1
Waiting for transaction b3324bb4516cff679a889b81361ca43ffeccdfa58720c89d791811eb9025adf6 ...Done (mined in block 2)
```
4. Publish the encrypted document, access policy and proving key for Bob to access. The directory `share` is shared between Alice and Bob (e.g. cloud storage).
```
root@alice:/usr/app# cp encrypted policy.json proving.key share/
```

#### Bob (document requester)

Log into Bob `docker-compose exec bob bash` and access the document with id `e538de4cf985ee2da48c49305c1ebb01b16f10adb527689b8a0be4c0178e79c1`
```
root@bob:/usr/app# ./client -c share/bob-config.json access --encrypted-document share/encrypted --document-id e538de4cf985ee2da48c49305c1ebb01b16f10adb527689b8a0be4c0178e79c1 --policy share/policy.json --proving-key share/proving.key 1 2 3 4
```
The `1 2 3 4` are the private authorization information Bob uses to fulfill the policy.

The document was successfully decrypted
```
root@bob:/usr/app# cat document
Alice's document
```
