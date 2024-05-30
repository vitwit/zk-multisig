# Multisig SNARK Account
- create N number of private-public key pairs (eddsa) offchain
- Create a multisig SNARK account from the N public keys and a decided T threshold number
- when a transaction needs to done from the multisig account, atleast T of N number of people should sign it, only then can the prover run the prover algorithm and generate zk proof, which will act as the sign bytes for the transaction
- If any one signs wrong message and claim that the signature is signed, the prover algorithm will throw error regardless if there are >= T number of valid signatures signed. (though if prover wants make transaction, he can filter out the invalid signatures and create a valid witness out of the remaining >= T valid signatures)


Note: inside the circuit define method, 
there is no way to skip the verification for unsigned signature (threshold case)
```
// we can't do as the inputs to the circuits are not comparable
if (signed[index] == 0) {
    continue // skip
} else {
    eddsa.Verify(curve, sign, msg, pubkey, &mimc) // check the signature
}

```

To work around this,
we used a some random signature to bypass it. the random signature doesn't have to be meaningful, just ANY one valid random signature with one valid pubkey will do. It held no other significance other than bypassing the signature verification check.

### To install simd binary

```
cd simapp
go install ./simd
```

You should now have a `simd` that supports the new zk account using gnark! 

## To Run

### To configure Number of Members and Threshold in the multisig account
- go to 
    crypto/keys/gnark/multisig_eddsa/multisig_eddsa.go

change the variables
```
const (
	MembersCount = 6
	Threshold    = 3
)
```

### To generate eddsa priv keys, pubkeys and create a Multisig account
    cd simapp
    cd gnarkcli
    cd multsig
    go run circuit.go

Store the bech32Address. The further logs are for test the multisig account. You make encounter proof generation failed but that's just a test. It happens because the threshold number of signatures didn't sign. It's random, you can change the code and play around with it.

### To run the chain
    cd simapp
    initSimapp.sh

Change the bech32Address ADDR inside initSimapp.sh script and run the script,
    bash initSimapp.sh
    simd start



### Generate, Sign, and Broadcast a Tx

create an unsigned tx to send funds from this account to another
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
txs.

Finally we can broadcast the tx:

```
simd tx broadcast signed.json
```

Query the balances to confirm if the transaction is done !!!


