package gnark

import (
	"bytes"
	crand "crypto/rand"
	"crypto/subtle"
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

	// hash to curve
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

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

const (
	keyType = "groth16.bn254"
)

//-------
// define a specific circuit
// this should be independent of the key implementation and should be moved elsewhere
// the Pubkey/Privkey defined here should not depend on the circuit at all (only the proving/verifying keys generated from it)
//
// however there is one requirement: the circuit struct (witness) MUST begin with the Message (hash of the tx signBytes).
// this is because the message in the circuit witness can only be a single field element,
// but we need to pass in the full tx bytes in VerifySignature, so we need to be able to check
// the hash of the tx bytes equal the Message in the witness. Since we don't want to depend directly on the witness structure (it could be an arbitrary circuit)
// we just require the first element in the witness is the Message so we can at least fetch that.

// TODO: write other example circuits

type eddsaCircuit struct {
	Message   frontend.Variable `gnark:",public"`
	Signature eddsa.Signature   `gnark:",public"`

	// we use a closure for the Define method so we can hardcode the public key into the circuit
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

func GenKeys() (signature.Signer, signature.PublicKey) {
	// create a eddsa key pair
	privateKey, err := eddsacrypto.New(tedwards.BN254, crand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.Public()

	return privateKey, publicKey
}

// returns msgToSign (msg hashed to curve) and eddsa signature
func SignMsg(privateKey signature.Signer, msg []byte) ([]byte, []byte) {

	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	msgToSign := GetMsgToSign(msg)

	// sign the message
	signature, err := privateKey.Sign(msgToSign, hFunc)
	if err != nil {
		panic(err)
	}

	// verifies signature
	isValid, err := privateKey.Public().Verify(signature, msgToSign, hFunc)
	if err != nil {
		panic(err)
	}
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}
	return msgToSign, signature
}

//---------------------------
// PrivKey (Prover)

var (
	_ cryptotypes.PrivKey = &PrivKey{}
)

func (p PrivKey) Bytes() []byte {
	return p.ProvingKey
}

// msg is the private witness.
// returns the proof
func (p PrivKey) Sign(msg []byte) ([]byte, error) {

	cs := groth16.NewCS(ecc.BN254)
	_, err := cs.ReadFrom(bytes.NewBuffer(p.ConstraintSystem))
	if err != nil {
		return nil, err
	}

	pk := new(bn254.ProvingKey)
	_, err = pk.ReadFrom(bytes.NewBuffer(p.ProvingKey))
	if err != nil {
		return nil, err
	}

	// create new witness and unmarshal msg
	privateWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	err = privateWitness.UnmarshalBinary(msg)
	if err != nil {
		return nil, err
	}

	// generate the proof
	proof, err := groth16.Prove(cs, pk, privateWitness)
	if err != nil {
		return nil, err
	}

	// marshal the proof
	proofbn254 := proof.(*bn254.Proof)
	proofBytes, err := json.Marshal(proofbn254)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil
}

func (p PrivKey) PubKey() cryptotypes.PubKey {
	return &PubKey{p.VerifyingKey}
}

func (p PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	return p.Type() == other.Type() && subtle.ConstantTimeCompare(p.Bytes(), other.Bytes()) == 1
}

func (p PrivKey) Type() string {
	return keyType
}

// -----------
// PubKey - verifier

var (
	_ cryptotypes.PubKey = &PubKey{}
)

// Signature is a "zk signature" for gnark containing the ProofBytes and the WitnessBytes
type Signature struct {
	ProofBytes   []byte
	WitnessBytes []byte
}

// msg is the original tx data to be signed
// sig is the marshalled Signature, including proof and witness data
// CONTRACT: the first element in the Signature.WitnessBytes unmarshalled from the sigBytes is the
// Message, which must be equal to the hash of the `msg` argument for this to be valid.
func (v PubKey) VerifySignature(msg, sigBytes []byte) bool {

	sig := new(Signature)
	err := json.Unmarshal(sigBytes, sig)
	if err != nil {
		return false
	}

	// unmarshal sig into proof
	proof := new(bn254.Proof)
	err = json.Unmarshal(sig.ProofBytes, proof)
	if err != nil {
		return false
	}

	// create new witness and unmarshal msg
	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return false
	}

	err = publicWitness.UnmarshalBinary(sig.WitnessBytes)
	if err != nil {
		return false
	}

	// first element in the vector is the Message
	vec := publicWitness.Vector()
	msgElement := vec.(fr.Vector)[0] // !
	msgBytes := msgElement.Bytes()

	// hash the msg to curve
	msgHashed := GetMsgToSign(msg)

	// check hash(msg) == sig.Message
	if !bytes.Equal(msgHashed, msgBytes[:]) {
		return false
	}

	vk := new(bn254.VerifyingKey)
	_, err = vk.ReadFrom(bytes.NewBuffer(v.Key))
	if err != nil {
		return false
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
	return keyType
}

//-------
// helper funcs

// returns a test msg
func GetMsg() []byte {
	// base  message is 4 bytes
	msgUnpadded := []byte{0xde, 0xad, 0xf0, 0x0d}
	// msg can be any size (even bigger than 32)
	msg := make([]byte, 100)
	// put it somewhere it crosses a 32-byte boundary for fun
	copy(msg[28:], msgUnpadded)
	return msg
}

// hash the msg to the curve using fr.Hash
func GetMsgToSign(msg []byte) []byte {
	elems, err := fr.Hash(msg, nil, 1)
	if err != nil {
		panic(err)
	}
	elb := elems[0].Bytes()
	msgToSign := elb[:]
	return msgToSign
}
