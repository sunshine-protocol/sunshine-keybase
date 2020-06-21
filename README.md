# Sunshine Identity Module


implementation of [Keybase Local Key Security](https://book.keybase.io/docs/crypto/local-key-security) on substrate, using [ipfs-rust/ipfs-embed](https://github.com/ipfs-rust/ipfs-embed)

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

## Setup your account

Set your device key to `//Alice`:

```bash
cli-identity key set --suri //Alice
Please enter a new password (8+ characters):

Your device id is 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
Your user id is 0
```

Add a paper backup for your account:

```bash
cli-identity device paperkey
Generating a new paper key.
Here is your secret paper key phrase:

mandate robust earth scan shrimp second pipe pitch eternal snap glare tooth
bean crucial river bar crash nice sorry laundry oppose filter aunt swear

Write it down and keep somewhere safe.
```

and list your device keys:

```bash
cli-identity device list
5Fe8Da8o2TQY6heaopRA9Zs2dpiJ2GFtvWThnd89uxYEXK1q
5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
```

## Prove your online identity

Add a new online identity:

```bash
cli-identity id prove dvc94ch@github
Claiming dvc94ch@github...
Please *publicly* post the following Gist, and name it 'substrate-identity-proof.md'.

### substrate identity proof

I hereby claim:

  * I am dvc94ch on github.
  * I am 0 on the substrate chain with genesis hash mzyTJZVm7IXDUBeZwyWk6rG1YGIt8BQnNzrshKJCalYI.
  * I have a public key 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY valid at block with hash mfBFseDYNX31Poqei8A/9teYmxJIj4PFROoKLKEPaStE.

To claim this, I am signing this object:

{"block":[124,17,108,120,54,13,95,125,79,162,167,162,240,15,253,181,230,38,196,146,35,224,241,81,58,130,139,40,67,218,74,209],"body":{"Ownership":[{"Github":["dvc94ch"]}]},"ctime":1591448931056,"expire_in":18446744073709551615,"genesis":[207,36,201,101,89,187,33,112,212,5,230,112,201,105,58,172,109,88,24,139,124,5,9,205,206,187,33,40,144,154,149,130],"prev":null,"public":"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY","seqno":1,"uid":0}

with the key 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY, yielding the signature:

mAU6Gon1dqctnS/zPKHd9gWFvEJBqADvgYQy0OFuamA5CwVQk7papR0xBq8DijRqSXVGpJtNFmy7aYJk5cGLxv4c

And finally, I am proving ownership of the github account by posting this as a gist.
```

and list your identities:

```bash
cli-identity id list
Your user id is 0
dvc94ch@github https://gist.github.com/da8bbf9c69976a3d750e2c433126852b
```

## Receive payments to your public identity

Transfer a balance from `//Bob` to `dvc94ch@github`:
```bash
cli-identity --path /tmp/bob key set --suri //Bob
Please enter a new password (8+ characters):

Your device id is 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
Your user id is 1
```

make sure ipfs is running so that `//Bob` can fetch `//Alice`'s identity:

```bash
cli-identity run
```

finally make the transfer:

```bash
cli-identity --path /tmp/bob wallet transfer dvc94ch@github 10000
transfered 10000 to 5Fe8Da8o2TQY6heaopRA9Zs2dpiJ2GFtvWThnd89uxYEXK1q
```
