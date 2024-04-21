# gnarkcli

This is a demo of adding a zk account type to the SDK.

It was inspired by my recent comment in the Celestia forum on adding ZK to the base layer: https://forum.celestia.org/t/celestia-snark-accounts-design-spec/1639/9?u=ebuchman

It's an implementation of what I call an `e-snac` in there (an end-user snark
account).

[Get started right away](#let-me-play) or read on for how it works.

## Pubkey.Gnark

The idea to add this to the SDK is quite simple. The SDK defines a generic
PubKey interface, and every account has a PubKey. So the idea here is to define
a new PubKey type that is actually a zk verification key. This way we require
the absolute minimum number of changes to the SDK - no changes to the account
structure or anything else really, just a new PubKey type, defined in
`crypto/keys/gnark`, with the corresponding proto file in
`proto/cosmos/crypto/gnark`.

There is also a corresponding PrivKey type, which just wraps the circuit's
underlying proving key and constraint system. Everything is implemented using
the underlying bytes so there is no dependence on the circuit's data types once
it's been compiled.

The core of the SDK's PrivKey and PubKey interfaces are the `PrivKey.Sign(msg)`
and `PubKey.VerifySignature(msg, sig)`. In our world, `PrivKey.Sign` is really
the prover (taking in witness data, outputing a zk proof), and
`PubKey.VerifySignature` is the zk verifier. For `PubKeyVerifySignature(msg,
sig)`, the `msg` argument is the tx bytes (passed in standard by the SDK itself) and the `sig`
contains serialized proof and witness data (initially passed in by the user as
part of their "signed" tx)

The `PubKey.Address` is defined as expected, as the SHA256 hash of the
underlying verification key. From the perspective of the blockchain, the address
itself gives no indication of what kind of key it is!

The `gnark` module uses `groth16` as the proving system and the `bn254` curve,
as these were easy to get started with. In principle we could add other pairs of
proving system and curve, though these should likely be their own separate
modules and pubkey types. 

Note groth16 requires a trusted setup. In this case, the setup is done independently for each account 
by the users of the account. Since each account can define its own circuit, a
new setup must be done each time. For accounts designed to be used by many
users, this isn't great, but for accounts with a limited number of users, like a
zk multisig, the setup requires basically the same kind of work and trust assumptions as
seting up a normal multisig.

To activate the new `gnark` pubkey type in the SDK took only a few extra lines.
We had to add 2 lines in `crypto/codec/proto.go` to
register the new types, and 2 lines in `x/auth/ante/sigverify.go` to charge gas
for the new pubkey type when verifying a tx. For now it's just charging the same
as a secp256k1 key, but it should have something a bit more sophisticated (ie.
charge based on the size of the verification key, proof, and witness data).

## Circuits

The new `gnark` module is designed to work with arbitrary circuits defined by
users. The only thing it takes in are serialized bytes of the circuit's keys and
constraint system. This means users can play with new circuits without having to
recompile the main chain binary or update the chain (!). Of course since we use
groth16 for now they need to do a trusted setup for each new circuit.

There is an example circuit in `crypto/keys/gnark/eddsa`. It's a simple eddsa
signature from a single key. This has the same functionality as a normal SDK
signature, except the underlying public key is never revealed, and instead of
verifying the eddsa signature directly on chain, a zero knowledge proof of the
eddsa signature verification is verified instead. 

This is kind of a trivial example, but useful as a starting point. A slightly more interesting example 
would be a zk multisig. A normal SDK multisig requires all the pubkeys of the
multisig to be stored on chain, and whenever a tx is signed, its clear which
pubkeys in the multisig signed for it. With a zk multisig, only the circuit's
verification key is stored on chain. The underlying pubkeys are never revealed,
nor is it revelead which of them signed a given tx.

## Let me play

Certainly. 

### Install Simd

First, install the `simd` binary. From the root:

```
cd simapp
go install ./simd
```

### Compile the Circuit

Now let's compile the example circuit:


```
cd gnarkcli
mkdir keys
go run circuit.go
```

We're using the simple eddsa single sig circuit here.
This will write the relevant keys to the `keys` dir. It will also output the address
corresponding to the verification key, eg.:

```
Bech32 Account Address: cosmos1e9z5esedugxf9vlv9c7jh4df3lqkqakq3aap9k
```

This is the address of your zk account!

Lets save this address (whatever it spits out for you) for use later:

```
# replace with whatever your Bech32 Account Address is
# eg. export ADDR=cosmos1e9z5esedugxf9vlv9c7jh4df3lqkqakq3aap9k
export ADDR=< ... > 
```

### Setup a New Chain

To clear your existing simapp data and setup a new chain:

```
rm -rf ~/.simapp
simd init abed --chain-id my-zk-test-chain
simd keys add me --keyring-backend test
simd genesis add-genesis-account me 100000000000stake --keyring-backend test
simd genesis add-genesis-account $ADDR 100000stake  --keyring-backend test
simd genesis gentx me 100000000stake --chain-id my-zk-test-chain --keyring-backend test
simd genesis collect-gentxs 
```

This will make a new chain with chain-id `my-zk-test-chain` and a new key (secp256k1) called
`me`. It will give a bunch of `stake` to that new key's address, and will create
a validator with it so the chain can run. It will also create an account with
some `stake` for the new zk account we created.


Create a separate window (so you don't lose your $ADDR) and start the chain:

```
simd start
```

Back in the original window, query the zk account. It should have a balance.
Here's what I get:

```
$ simd query bank balances $ADDR
balances:
- amount: "100000"
  denom: stake
```

### Generate, Sign, and Broadcast a Tx

Now we can generate an unsigned tx to send funds from this account to another
account:

```
simd tx bank send $ADDR cosmos1glx97c5kfkjvjyvmue2lja5ercy3muff37ehs8 100stake --generate-only  | jq . > unsigned.json
```

I just used a random address `cosmos1glx97c5kfkjvjyvmue2lja5ercy3muff37ehs8` to
send to. Also note I used `jq` to pretty print the JSON, and saved it to
`unsigned.json`. 

This account should be empty to begin with:

```
simd query bank balances cosmos1glx97c5kfkjvjyvmue2lja5ercy3muff37ehs8
```

To sign this tx (using the zk proof!), run the following:

```
go run cli.go 0
```

The 0 is the sequence number, and should be incremented if you do subsequent
txs. Everything else is hardcoded in the `cli.go` file. This command will write
a signed version of the tx to `signed.json`. Check out the large pubkey and
signature in that tx!

Finally we can broadcast the tx:

```
simd tx broadcast signed.json
```

It should succeed! Now if we query the account, it should no longer be empty:


```
simd query bank balances cosmos1glx97c5kfkjvjyvmue2lja5ercy3muff37ehs8
```

And the balance from your zk account should have been reduced!


```
simd query bank balances $ADDR
```

CONGRATS! You just sent a cosmos-sdk tx using a zk proof!


