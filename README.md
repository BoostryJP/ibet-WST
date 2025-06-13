# ibet-WST 🌏

## Overview

ibet-WST (ibet Worldwide Settlement Token) is a protocol that bridges security tokens (digital securities) on the ibet for Fin consortium blockchain to the Ethereum network, enabling global DvP (Delivery versus Payment) settlement on public blockchains.

- [IbetWST](contracts/IbetWST.sol): The main contract for ibet-WST. It is implemented as an extension of the ERC20 token standard, providing whitelist management for holders and DvP settlement functionality.
- [AuthIbetWST](contracts/AuthIbetWST.sol): An extension of the IbetWST contract that adds authentication using EIP-712 signatures. This enables gasless transactions for various ibet-WST functions.

![img.png](img.png)

## Install

Install 3rd-party package modules:
```
$ make install
```

Install OpenZeppelin contracts:
```
$ brownie pm install OpenZeppelin/openzeppelin-contracts@5.3.0
```

Install Hardhat as a Node.js package:
```
$ npm install
```

## Developing Smart Contracts

### Brownie settings

Import network settings into Brownie:
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
