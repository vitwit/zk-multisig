package gnark

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"

	// cosmos and comet
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"

	// local util
	gnarkutil "github.com/cosmos/cosmos-sdk/crypto/keys/gnark/util"

	// gnark backend, proof system, curve
	"github.com/consensys/gnark/backend/groth16"
	bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"

	// gnark hashing and signature
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	keyType = "groth16.bn254"
)

// the Pubkey/Privkey defined here do not depend on the circuit at all (only the proving/verifying keys generated from it)
//
// however there is one requirement: the circuit struct (witness) MUST begin with the Message (hash of the tx signBytes).
// this is because the message in the circuit witness can only be a single field element,
// but we need to pass in the full tx bytes in VerifySignature, so we need to be able to check
// the hash of the tx bytes equal the Message in the witness. Since we don't want to depend directly on the witness structure (it could be an arbitrary circuit)
// we just require the first element in the witness is the Message so we can at least fetch that.
//
// see the example in crypto/keys/gnark/eddsa

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
	msgHashed := gnarkutil.HashMsg(msg)

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
// helper func

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
