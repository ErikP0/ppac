### About

This is a **prototype** implementation of a distributed key-management system with privacy-preserving access control.

Key management is distributed among policy enforcement (PEP) nodes that use secret-sharing and various threshold
cryptography protocols to generate, manage and re-encrypt key material.

Access policies to keys are encoded as zero-knowledge proof statements in the [ZoKrates](https://github.com/zokrates/zokrates) format.
A requester then creates a zk-snark proof over the given statement and uses this proof as authorization. The proof is
checked in a smart contract in a (private) Ethereum blockchain.

In short:

 * Keys are secret-shared and thus partial compromise of PEP nodes is tolerated
 * A requester uses a privacy-preserving authorization with minimal release of information

The implementation consists of three parts
 - The PEP node implementation [secret-store](/secret-store)
 - The client implementation [client](/client)
 - The smart contract in [contracts](/contracts)

### Building

Make sure that the submodule is pulled: `git submodule update --init`.

Prerequisites:
- Rust installation supporting Rust 2018 with `stable` and `nightly` toolchains available to `Cargo`

All build commands and steps are abbreviated via `make`

Type `make` to see list of all targets,
```
client             Builds the client
client-test        Runs client tests
secretstore        Builds secretstore server
secretstore-test   Runs secretstore server tests
```

The binaries for `make client` and `make secretstore` can be found in `target/client` and `target/secretstore` respectively.

`secretstore-test` is fast to build and run while `client-test` will take a while to compile at the first run as a full secretstore instance will be built to run tests against.

### Docker
There are docker images for the client and secretstore server available.

They can be build manually via `docker build -f [client|secretstore].Dockerfile .`.

Pre-built images are available from the GitHub package repository:
```
docker pull docker.pkg.github.com/erikp0/ppac/secretstore:latest
```
and
```
docker pull docker.pkg.github.com/erikp0/ppac/client:latest
```

### Demo

See [demo](/demo) directory.

### License
Parts of this work use code from Parity's [secret-store](https://github.com/paritytech/secret-store) implementation licensed under GPL3.
