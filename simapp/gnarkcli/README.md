# gnarkcli

This is a demo of adding a zk account type to the SDK (v0.50) using [gnark](https://github.com/Consensys/gnark) (groth16 and bn254). This allows a Cosmos-SDK account to be controlled by an arbitrary user-defined off-chain ZK circuit.

It was inspired by my recent comment in the Celestia forum on adding ZK to the base layer: https://forum.celestia.org/t/celestia-snark-accounts-design-spec/1639/9?u=ebuchman

It's an implementation of what I call an `e-snac` in there (an end-user snark
account).

[Get started right away](#let-me-play) or read on for how it works.

## Pubkey.Gnark

The SDK defines a [generic PubKey interface](/crypto/types/types.go#L9), and every account has a PubKey. So the idea here is to define
a new PubKey instance type that is actually a zk verification key. This way we require
the absolute minimum number of changes to the SDK - no changes to the account
structure or anything else really, just a new concrete PubKey type, defined in
[`crypto/keys/gnark`](/crypto/keys/gnark), with the corresponding proto file in
[`proto/cosmos/crypto/gnark`](/proto/cosmos/crypto/gnark/keys.proto).

There is also a corresponding PrivKey type, which just wraps the circuit's
underlying proving key and constraint system. Everything is implemented using
serialized bytes so that once a circuit is compiled, there is no dependence on the circuit's data types.

The core of the SDK's PrivKey and PubKey interfaces are the `PrivKey.Sign(msg)`
and `PubKey.VerifySignature(msg, sig)`. Normally, these are elliptic curve signing and signature verification 
methods. In our world, `PrivKey` is a zk prover and `Pubkey` is a zk verifier, so `PrivKey.Sign` produces a zk proof
and `PubKey.VerifySignature` verifies one. For `PubKeyVerifySignature(msg,
sig)`, the `msg` argument is the tx bytes (passed in standard by the SDK itself) and the `sig`
contains serialized proof and witness data (initially passed in by the user as
part of their "signed" tx)

The `PubKey.Address` is defined as expected, as the SHA256 hash of the
underlying verification key. From the perspective of the blockchain, the address
itself gives no indication of what kind of key it is or of what circuit it pertains to. 
This means we can make normal Cosmos-SDK accounts
that are controlled by _arbitrary_ ZK circuits. So it's like a smart-contract-based account but without
needing a VM on chain. The circuits themselves are defined completley off chain. The only thing that
goes on chain is the verification key!

The new [`gnark`](https://github.com/informalsystems/cosmos-sdk/tree/gnark50/crypto/keys/gnark) key type module 
uses `groth16` as the proving system and the `bn254` curve,
as these were easy to get started with. In principle we could add other pairs of
proving system and curve, though these should likely be their own separate
modules and pubkey types. 

To that effect, the module and the key type really shouldnt be called `gnark`,
but probably `groth16bn254` or something like that ... LM.

Note groth16 requires a trusted setup. In this case, the setup is done independently for each account 
by the users of the account. Since each account can define its own circuit, a
new setup must be done each time. For accounts designed to be used by many
users, this isn't great, but for accounts with a limited number of users, like a
zk multisig, the setup requires basically the same kind of work and trust assumptions as
setting up a normal multisig.

To activate the new `gnark` pubkey type in the SDK took only a few extra lines.
We had to add 2 lines in `crypto/codec/proto.go` to
register the new types, and 2 lines in `x/auth/ante/sigverify.go` to charge gas
for the new pubkey type when verifying a tx. For now it's just charging the same
as a secp256k1 key, but it should have something a bit more sophisticated (ie.
charge based on the size of the verification key, proof, and witness data).

## Circuits

The new `gnark` module is designed to work with arbitrary circuits defined by
users off-chain. The only thing it takes in are serialized bytes of the circuit's keys and
constraint system. This means users can play with new circuits without having to
recompile the main chain binary or update the chain (!). Of course since we use
groth16 for now they need to do a trusted setup for each new circuit.

There are two example circuits, [`crypto/keys/gnark/eddsa`](https://github.com/informalsystems/cosmos-sdk/blob/gnark50/crypto/keys/gnark/eddsa/eddsa.go#L35) and [`crypto/keys/gnark/password`](https://github.com/informalsystems/cosmos-sdk/blob/gnark50/crypto/keys/gnark/password/password.go#L23). 
The `eddsa` circuit does a simple eddsa
signature verification from a single key, using an eddsa pubkey built into the circuit. 
This has the same functionality as a normal SDK
signature, except the underlying public key is never revealed, and instead of
verifying the eddsa signature directly on chain, a zero knowledge proof of the
eddsa signature verification is verified instead. The `password` circuit just checks that you 
 know some secret value (by checking the result of hashing it with some public data), where the secret
 itself is included in the circuit. This effectively allows you to send transactions from an account just by knowing
some password (without even needing a real private key or doing any kind of signing!). In both cases the user specific info (either an eddsa key or a password) is included in the circuit, so each time a user instatiates one of these circuits they'll get a different verification key and thus a different address (unless they use the same eddsa pubkey or the same secret password!).

These are simple examples, but useful as starting points. A slightly more interesting example 
would be a zk multisig, or a zk login account. A normal SDK multisig requires all the pubkeys of the
multisig to be stored on chain, and whenever a tx is signed, its clear which
pubkeys in the multisig signed for it. With a zk multisig, only the circuit's
verification key is stored on chain. The underlying pubkeys are never revealed,
nor is it revelead which of them signed a given tx. With a zk login account, users would be able to send Cosmos-SDK txs using Oauth logins.

## Let me play

Certainly. 

### Install Simd

If you don't already have a copy of the Cosmos-SDK locally, clone it: `git clone https://github.com/cosmos/cosmos-sdk`.

Now from the SDK repo, fetch this fork and check out the `gnark50` branch. From your local Cosmos-SDK repo:

```
git remote add informal https://github.com/informalsystems/cosmos-sdk
git fetch informal gnark50
git checkout informal/gnark50
```

Now, install the modified `simd` binary. `simd` is the SDK's built in example application. We can use it to test new functionality.

From the SDK repo (make sure you're on our branch):

```
cd simapp
go install ./simd
```

You should now have a `simd` that supports the new zk account using gnark! 

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
# in a new window!
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

And if we query the account data, we see it has no specified pubkey yet. 
In the cosmos-sdk, an account's pubkey is only added to the account once it
sends its first transaction. Since we haven't sent a tx from this account yet,
the chain doesn't know its pubkey (or even that its actually a zk account with a
verification key!) 

```
$simd query auth account $ADDR
account:
  type: cosmos-sdk/BaseAccount
  value:
    account_number: "1"
    address: cosmos1e9z5esedugxf9vlv9c7jh4df3lqkqakq3aap9k
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
a signed version of the tx to `signed.json` (it will also dump it to your screen). Check out the large pubkey and
signature in that tx! The pubkey in there is the circuit's verification key and
the signature is the zk proof and the witness data.

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

Finally, you can see that the verification key is now stored in the account on-chain:

```
$ simd query auth account $ADDR
account:
  type: cosmos-sdk/BaseAccount
  value:
    account_number: "1"
    address: cosmos1e9z5esedugxf9vlv9c7jh4df3lqkqakq3aap9k
    public_key:
      type: tendermint/PubKeyGnark
      value: gwlWvpboM9nw6tMuQO3NZfRusby0JSyCRixtCl9u19GXuYqEbUcu4DsmD33HsZJZGSY5OciPngJjCsVJApP1lMwlgSxnj76uWByubqW5L1U0uuxOVeiCHWjuUh0C7SOYIWOWi3ImUtaPofWlIAow7R+BM+2apomHYgANcZzC4zaJUzOHzj2naIehkSQIzh801zpynDgblOg3EWXv07pHUxa2YxpYoe9B/fVijZacfSq2GjNHygjzC/N4ML+z4XKLp6SrsKGZMOK7Jr3svLNc3ZAitK/vTpxX+CPXwFat8CeB26duYGX12bdhhjMz0THXj6J7Nfe/ZXJAbSX/v2rhKCsISheVtUvGldKVbch6CgIGKngB5GxKDu3eJpc/mMxBAAAAAoajg7mPEk5YI6K4MrxPZXT8XkXZBu8V7gZVOelj+BD7ghL21RYtkPx4y7Z1JZjUZmAT0ozkj9x9idOJxPmw2IAAAAAAiev2BQt5xKlt+vpi+lkupiYY5BE8ernBf/siNEBj7sEaYitadZcMSLFRbEfRBJuVkJ5RTgVPGajg8itPThmcQsg3QRrylTdsD9C17llRR1M+Lp19EXm8YDb9wEQuNKuwAp92/dq/7kpaqRLF8C51v4pvpLIXpWNtPFYnSLX0jsk=
    sequence: "1"
```

This key is the only information about the circuit stored on chain, and each
different circuit or instantiation of a circuit with different data will have its own verification
key stored in the account on chain once it makes its first transaction.

You can now send more txs by incrementing the sequence number, ie.

```
go run cli.go 1
```

To send different kinds of txs, generate a new `unsigned.json`

---

CONGRATS! You just sent a cosmos-sdk tx using a zk proof!

Now try to build you're own circuit and copy these `circuit.go` and `cli.go` scripts to test them out!
