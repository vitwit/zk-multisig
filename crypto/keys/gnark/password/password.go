package password

import (

	// local util
	gnarkutil "github.com/cosmos/cosmos-sdk/crypto/keys/gnark/util"

	// gnark backend and frontend
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	// compile circuit
	"github.com/consensys/gnark-crypto/ecc"

	// hash func
	hash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/hash/mimc"
)

type passwordCircuit struct {
	Message   frontend.Variable `gnark:",public"`
	Signature frontend.Variable

	// we use a closure for the Define method so we can hardcode the password into the circuit
	define func(api frontend.API) error
}

func (circuit *passwordCircuit) Define(api frontend.API) error {
	return circuit.define(api)
}

// reutrn the define func as a closure so we can hardcode the public key as part of the circuit
func (circuit *passwordCircuit) defineWithPassword(password []byte) func(frontend.API) error {
	return func(api frontend.API) error {

		mimc, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}

		// circuit.Signature == Hash(circuit.Message | password)
		mimc.Write(circuit.Message)
		mimc.Write(password)
		sum := mimc.Sum()
		api.AssertIsEqual(sum, circuit.Signature)
		return nil
	}
}

func CompileCircuit(password []byte) (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem) {
	var circuit passwordCircuit

	// fixed pubkey should be part of circuit
	circuit.define = circuit.defineWithPassword(password)

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
	var assignment passwordCircuit

	// assign message value
	assignment.Message = msg

	// assign signature values
	assignment.Signature = signature

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

// returns hash(msg) and hash( hash(msg) | hash(password) )
func SignMsg(password, msg []byte) ([]byte, []byte) {

	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	msgToSign := gnarkutil.GetMsgToSign(msg)
	pwdHash := gnarkutil.GetMsgToSign(password)

	// sign the message
	hFunc.Write(msgToSign)
	hFunc.Write(pwdHash)
	signature := hFunc.Sum(nil)

	return msgToSign, signature
}
