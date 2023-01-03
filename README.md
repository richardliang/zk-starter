# ZK Starter

Starter repo for writing Circom circuits

## Build

First, you must have the Circom 2 compiler installed. See [installation
instructions](https://docs.circom.io/getting-started/installation/) for details.

The build step compiles the circuit, does untrusted setup, generates verifier contract, and compiles all the contracts. It could take a while at the setup step.

```sh
yarn install
yarn build
```

```sh
yarn test
```

## Benchmark

```sh
yarn run info
```
