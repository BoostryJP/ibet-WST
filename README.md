# ibet-WST 🌏

## Overview

ibet-WST (ibet Worldwide Settlement Token) is a protocol that bridges security tokens on the ibet for Fin consortium blockchain with EVM networks, including Ethereum, enabling global DvP (Delivery versus Payment) settlement on public blockchains.

- [IbetWST](contracts/token/IbetWST.sol): The main contract for ibet-WST. It is implemented as an extension of the ERC20 token standard, providing whitelist management for holders and DvP settlement functionality.
- [AuthIbetWST](contracts/token/AuthIbetWST.sol): An extension of the IbetWST contract that adds authentication using EIP-712 signatures. This enables gasless transactions for various ibet-WST functions.

![img.png](img.png)

## Workflows

### Mint & Burn

<img width="1309" height="837" alt="image" src="https://github.com/user-attachments/assets/0686d5b8-ac35-4f0b-9b1c-ff7cd63f1a21" />

### DVP

<img width="1309" height="837" alt="image" src="https://github.com/user-attachments/assets/1c6c29ee-5ca1-4c2a-a988-25f7bb14086b" />

## Install & Setup

Install 3rd-party package modules:
```
$ make install
```

Setup the development environment:
```
$ make setup
```

This installs Ape plugins and Solidity dependencies for local Foundry-based development.

## Developing Smart Contracts


### Compile Contracts

You can compile the smart contracts by running the following command:
```
$ make compile
```

### Running the tests

You can run the tests with:
```
$ make test
```

Or you can run the particular test file with:
```
$ make test {path_to_test_file}
```
