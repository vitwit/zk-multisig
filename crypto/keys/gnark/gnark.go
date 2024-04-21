package gnark

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"fmt"

	// cosmos and comet
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"

	// gnark backend and frontend
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	// curve
	bn254 "github.com/consensys/gnark/backend/groth16/bn254"

	// signature
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"

	// twisted edwards
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"

	// eddsa
	eddsacrypto "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/std/signature/eddsa"

	// hash func
	hash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/hash/mimc"
)

type eddsaCircuit struct {
	Signature eddsa.Signature   `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`

	define func(api frontend.API) error
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
	return circuit.define(api)
}

// reutrn the define func as a closure so we can hardcode the public key as part of the circuit
func (circuit *eddsaCircuit) defineWithPubkey(pubkey eddsa.PublicKey) func(frontend.API) error {
	return func(api frontend.API) error {
		curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
		if err != nil {
			return err
		}

		mimc, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		// verify the signature in the cs
		return eddsa.Verify(curve, circuit.Signature, circuit.Message, pubkey, &mimc)
	}
}

// Private Key
type Prover struct {
	pk groth16.ProvingKey
}

// -----------
// PubKey - verifier
var (
	_ cryptotypes.PubKey = &PubKey{}
)

// msg is the public witness
// sig is the proof
func (v PubKey) VerifySignature(msg, sig []byte) bool {

	// unmarshal sig into proof
	proof := new(bn254.Proof)
	err := json.Unmarshal(sig, proof)
	if err != nil {
		return false
	}

	// create new witness and unmarshal msg
	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return false
	}

	err = publicWitness.UnmarshalBinary(msg)
	if err != nil {
		panic(err)
	}

	vk := new(bn254.VerifyingKey)
	_, err = vk.ReadFrom(bytes.NewBuffer(v.Key))
	if err != nil {
		panic(err)
	}

	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return false
	}
	return true
}

func (v PubKey) Address() crypto.Address {
	return crypto.Address(tmhash.SumTruncated(v.Bytes()))
}

func (v PubKey) Bytes() []byte {
	return v.Key
}

func (v PubKey) String() string {
	return fmt.Sprintf("PubKeyGnark{%x}", v.Bytes())
}

func (v PubKey) Equals(other cryptotypes.PubKey) bool {
	return v.Type() == other.Type() && bytes.Equal(v.Bytes(), other.Bytes())
}

func (v PubKey) Type() string {
	return "groth16.bn254"
}

//-------
// helper funcs

func GetMsg() []byte {

	// note that the message is on 4 bytes
	msgUnpadded := []byte{0xde, 0xad, 0xf0, 0x0d}
	// msg expected to be 32 bytes
	msg := make([]byte, 32)
	copy(msg[28:], msgUnpadded)
	return msg
}

func GenKeys() (signature.Signer, signature.PublicKey) {
	// create a eddsa key pair
	privateKey, err := eddsacrypto.New(tedwards.BN254, crand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.Public()

	return privateKey, publicKey
}

func SignMsg(privateKey signature.Signer, msg []byte) []byte {

	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	// sign the message
	signature, err := privateKey.Sign(msg, hFunc)
	if err != nil {
		panic(err)
	}

	// verifies signature
	isValid, err := privateKey.Public().Verify(signature, msg, hFunc)
	if err != nil {
		panic(err)
	}
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}
	return signature
}

func CompileCircuit(publicKey signature.PublicKey) (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem) {
	var circuit eddsaCircuit

	// assign public key values
	// fixed pubkey should be part of circuit
	var pubKey eddsa.PublicKey
	_publicKey := publicKey.Bytes()
	pubKey.Assign(tedwards.BN254, _publicKey[:32])
	circuit.define = circuit.defineWithPubkey(pubKey)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	return pk, vk, cs

}

func PrepareWitness(msg, signature []byte) (witness.Witness, witness.Witness) {
	// declare the witness
	var assignment eddsaCircuit

	// assign message value
	assignment.Message = msg

	// assign signature values
	assignment.Signature.Assign(tedwards.BN254, signature)

	// witness
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	return witness, publicWitness

}
