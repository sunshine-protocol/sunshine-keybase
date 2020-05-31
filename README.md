# Substrate Identity Module

## Build

Build Wasm and native code:

```bash
cargo build --release
```

## Start the node

Purge any existing developer chain state:

```bash
./target/release/node-identity purge-chain --dev
```

Start a development chain with:

```bash
./target/release/node-identity --dev
```

## Use the cli

List your identities

```bash
./target/release/cli-identity id
```

or add a new online identity

```
./target/release/cli-identity prove dvc94ch@github
```
