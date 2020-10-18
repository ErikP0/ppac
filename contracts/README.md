This is a truffle project using ganache to mock the Ethereum blockchain.

The contract to be deployed as policy decision point is [SecretStore.sol](contracts/SecretStore.sol).

### Setup
Install `truffle` and `ganache-cli`
```
npm install truffle ganache-cli
```

### Compile & Test
Compile the contracts with
```
node_modules/.bin/truffle compile
```
and run a `ganache` instance in a separate window: `node_modules/.bin/ganche_cli`.

Then, tests can be run via
```
node_modules/.bin/truffle test
```
