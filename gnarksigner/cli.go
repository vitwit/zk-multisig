package gnarksigner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authclient "github.com/cosmos/cosmos-sdk/x/auth/client"
	authclientcli "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	"cosmossdk.io/log"
	"cosmossdk.io/simapp"
	dbm "github.com/cosmos/cosmos-db"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"

	// gnark key types
	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark"

	// gnark witness
	"github.com/consensys/gnark/backend/witness"
)

// sign a tx using the circuit and keys in local `keys` dir.
// this is all hacked together from the SDK client.

const (
	SIGN_MODE = signing.SignMode_SIGN_MODE_DIRECT

	UNSIGNED_FILE = "unsigned.json" // unsigned tx file to sign

)

// Signer holds data necessary for signing
type Signer struct {
	clientCtx client.Context
	txBuilder client.TxBuilder

	priv    *gnark.PrivKey
	chainID string
	accNum  int
	seqNum  int
}

// InitSigner initialized the signer and gets the sign bytes
func InitSigner() (*Signer, []byte, error) {
	cmd := authclientcli.GetSignCommand()

	clientCtx := client.Context{}

	// get a txConfig
	tempApp := simapp.NewSimApp(log.NewNopLogger(), dbm.NewMemDB(), nil, true, simtestutil.NewAppOptionsWithFlagHome(tempDir()))
	txCfg := tempApp.TxConfig()

	clientCtx = clientCtx.WithTxConfig(txCfg)

	clientCtx, txF, newTx, err := readTxAndInitContexts(clientCtx, cmd, UNSIGNED_FILE)
	if err != nil {
		return nil, nil, err
	}
	_ = txF // dont need it for anything?

	txBuilder, err := txCfg.WrapTxBuilder(newTx)
	if err != nil {
		return nil, nil, err
	}

	signer := &Signer{
		clientCtx: clientCtx,
		txBuilder: txBuilder,
	}

	signBytes, err := getSignBytes(signer)
	if err != nil {
		return nil, nil, err
	}

	return signer, signBytes, nil
}

func getSignBytes(signer *Signer) ([]byte, error) {
	clientCtx := signer.clientCtx
	txBuilder := signer.txBuilder

	txCfg := clientCtx.TxConfig

	//------------
	// Args

	// get the account's sequence number from the CLI
	seqNumStr := os.Args[1]
	seqNum, err := strconv.Atoi(seqNumStr)
	if err != nil {
		return nil, err
	}

	// TODO: dont hardcode, better interface for taking these
	chainID := "my-zk-test-chain"
	accNum := 1

	signer.chainID = chainID
	signer.accNum = accNum
	signer.seqNum = seqNum

	//---------------------------
	// read in and initialize the circuit keys

	vkBytes, err := ioutil.ReadFile("keys/vk")
	if err != nil {
		return nil, err
	}
	pkBytes, err := ioutil.ReadFile("keys/pk")
	if err != nil {
		return nil, err
	}
	csBytes, err := ioutil.ReadFile("keys/cs")
	if err != nil {
		return nil, err
	}

	// gnark (groth16.bn254) pub and privkeys
	gnarkPub := &gnark.PubKey{vkBytes}
	gnarkPriv := &gnark.PrivKey{
		ProvingKey:       pkBytes,
		VerifyingKey:     vkBytes,
		ConstraintSystem: csBytes,
	}

	signer.priv = gnarkPriv

	//---------------------------
	// build the tx signer data

	signerData := authsigning.SignerData{
		ChainID:       chainID,
		AccountNumber: uint64(accNum), // txf.AccountNumber(),
		Sequence:      uint64(seqNum), // txf.Sequence(),
		PubKey:        gnarkPub,
		Address:       sdk.AccAddress(gnarkPub.Address()).String(),
	}

	sigData := signing.SingleSignatureData{
		SignMode:  SIGN_MODE,
		Signature: nil,
	}
	sig := signing.SignatureV2{
		PubKey:   gnarkPub,
		Data:     &sigData,
		Sequence: uint64(seqNum),
	}

	err = txBuilder.SetSignatures(sig)
	if err != nil {
		panic(err)
	}

	//---------------------
	// much of what follows is ripped from the SDK's tx.SignWithPrivKey.
	// note we modify since we first sign with the hidden bn254 key and then produce the gnark proof

	// Generate the bytes to be signed.
	txSignBytes, err := authsigning.GetSignBytesAdapter(
		clientCtx.CmdContext, txCfg.SignModeHandler(), SIGN_MODE, signerData, txBuilder.GetTx())
	if err != nil {
		return nil, err
	}

	return txSignBytes, nil
}

// SignTx builds the zk proof and prepares the signed tx using the given msg and "signature"
func SignTx(signer *Signer, privateWitness witness.Witness, publicWitness witness.Witness) error {

	// marshal the witness
	privWitnessBytes, err := privateWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}
	pubWitnessBytes, err := publicWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// produce proof
	proofBytes, err := signer.priv.Sign(privWitnessBytes)
	if err != nil {
		panic(err)
	}

	// build the gnarkSig
	gnarkSig := gnark.Signature{
		ProofBytes:   proofBytes,
		WitnessBytes: pubWitnessBytes,
	}

	gnarkSigBytes, err := json.Marshal(gnarkSig)
	if err != nil {
		panic(err)
	}

	// Construct the SignatureV2 struct
	sigData := signing.SingleSignatureData{
		SignMode:  SIGN_MODE,
		Signature: gnarkSigBytes,
	}

	sigV2 := signing.SignatureV2{
		PubKey:   signer.priv.PubKey(),
		Data:     &sigData,
		Sequence: uint64(signer.seqNum),
	}

	// End tx.SignWithPrivKey
	//----------------------

	err = signer.txBuilder.SetSignatures(sigV2)
	if err != nil {
		return nil
	}

	var jsonBytes []byte
	printSignatureOnly := false
	jsonBytes, err = marshalSignatureJSON(signer.clientCtx.TxConfig, signer.txBuilder, printSignatureOnly)
	if err != nil {
		return err
	}

	fmt.Println(string(jsonBytes))

	var prettyJSON bytes.Buffer

	// Pretty print the JSON
	err = json.Indent(&prettyJSON, jsonBytes, "", "    ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile("signed.json", prettyJSON.Bytes(), 0666)
}

func marshalSignatureJSON(txConfig client.TxConfig, txBldr client.TxBuilder, signatureOnly bool) ([]byte, error) {
	parsedTx := txBldr.GetTx()
	if signatureOnly {
		sigs, err := parsedTx.GetSignaturesV2()
		if err != nil {
			return nil, err
		}
		return txConfig.MarshalSignatureJSON(sigs)
	}

	return txConfig.TxJSONEncoder()(parsedTx)
}

var tempDir = func() string {
	dir, err := os.MkdirTemp("", "simapp")
	if err != nil {
		dir = simapp.DefaultNodeHome
	}
	defer os.RemoveAll(dir)

	return dir
}

func readTxAndInitContexts(clientCtx client.Context, cmd *cobra.Command, filename string) (client.Context, tx.Factory, sdk.Tx, error) {
	stdTx, err := authclient.ReadTxFromFile(clientCtx, filename)
	if err != nil {
		return clientCtx, tx.Factory{}, nil, err
	}

	txFactory, err := tx.NewFactoryCLI(clientCtx, cmd.Flags())
	if err != nil {
		return clientCtx, tx.Factory{}, nil, err
	}

	return clientCtx, txFactory, stdTx, nil
}
