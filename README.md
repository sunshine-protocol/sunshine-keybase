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

Add a new online identity

```bash
> ./target/release/cli-identity prove dvc94ch@github
claiming github identity dvc94ch
### substrate identity proof

I hereby claim:

  * I am dvc94ch on github.
  * I am 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY on substrate.

To claim this, I am signing this object:

\```json
{"body":{"Ownership":[{"Github":["dvc94ch"]}]},"ctime":1591023745317,"expire_in":18446744073709551615,"prev":null,"seqno":0}
\```

with the key 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY, yielding the signature:

\```
mAaJ/tnTfg7oEzewOMwjVQ2v8anbTx40VFYVUNvuwNykL46CuQypjG7NmLV6zx1qEamxSROx+u7fN6FgN1jSDF4c
\```

And finally, I am proving ownership of the github account by posting this as a gist.
```

and list your identities

```bash
> ./target/release/cli-identity id
0 dvc94ch@github Active("https://gist.githubusercontent.com/dvc94ch/da8bbf9c69976a3d750e2c433126852b/raw/95d0318026e9318fdb1b970c2708e7376cfac9b6/substrate-identity-proof.md")
```
