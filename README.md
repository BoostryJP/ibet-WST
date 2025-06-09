# ibet-WST
ibet Worldwide Settlement Token

## Install

Install 3rd-party package modules.
```
$ make install
```

Install openzeppelin-contracts.
```
$ brownie pm install OpenZeppelin/openzeppelin-contracts@5.3.0
```

Install hardhat as a Node.js package.

```
$ npm install
```

## Developing Smart Contracts

### Brownie settings

Importing network settings to Brownie.

```
$ brownie networks import conf/networks.yml
```

### Compile Contracts
Use eth-brownie to compile contracts.

```
$ brownie compile
```

### Running the tests

You can run the tests with:
```
$ brownie test
```

Alternatively, you can use pytest and run it as follows.
```
$ pytest tests/
```
