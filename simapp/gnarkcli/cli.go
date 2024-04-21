package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
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

	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

// sign a tx using the circuit and keys in local `keys` dir.
// this is all hacked together from the SDK client.
func main() {

	// unsigned tx file to sign
	file := "unsigned.json"

	cmd := authclientcli.GetSignCommand()

	clientCtx := client.Context{}

	// get a txConfig
	tempApp := simapp.NewSimApp(log.NewNopLogger(), dbm.NewMemDB(), nil, true, simtestutil.NewAppOptionsWithFlagHome(tempDir()))
	txCfg := tempApp.TxConfig()

	clientCtx = clientCtx.WithTxConfig(txCfg)

	clientCtx, txF, newTx, err := readTxAndInitContexts(clientCtx, cmd, file)
	if err != nil {
		panic(err)
	}

	err = signTx(cmd, clientCtx, txF, newTx)
	if err != nil {
		panic(err)
	}

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

func signTx(cmd *cobra.Command, clientCtx client.Context, txf tx.Factory, newTx sdk.Tx) error {

	txCfg := clientCtx.TxConfig

	txBuilder, err := txCfg.WrapTxBuilder(newTx)
	if err != nil {
		return err
	}

	//------------
	// Args

	// get the account's sequence number from the CLI
	accSeqStr := os.Args[1]
	accSeq, err := strconv.Atoi(accSeqStr)
	if err != nil {
		return err
	}

	// TODO: dont hardcode, better interface for taking these
	chainID := "my-zk-test-chain"
	accNum := 1

	//---------------------------
	// read in and initialize the circuit keys

	vkBytes, err := ioutil.ReadFile("keys/vk")
	if err != nil {
		return err
	}
	pkBytes, err := ioutil.ReadFile("keys/pk")
	if err != nil {
		return err
	}
	csBytes, err := ioutil.ReadFile("keys/cs")
	if err != nil {
		return err
	}

	// gnark (groth16.bn254) pub and privkeys
	gnarkPub := &gnark.PubKey{vkBytes}
	gnarkPriv := &gnark.PrivKey{
		ProvingKey:       pkBytes,
		VerifyingKey:     vkBytes,
		ConstraintSystem: csBytes,
	}

	//---------------------------
	// read in and init the eddsa key. we sign with this key and then prove we did so.
	// this key's address is never revealed on chain!

	privBytes, err := ioutil.ReadFile("keys/priv")
	if err != nil {
		return err
	}

	// privKey is the hidden bn254 key
	privKey := new(eddsa.PrivateKey)
	privKey.SetBytes(privBytes)

	//---------------------------
	// build the tx signer data

	signMode := txf.SignMode()
	if signMode == signing.SignMode_SIGN_MODE_UNSPECIFIED {
		// use the SignModeHandler's default mode if unspecified
		signMode, err = authsigning.APISignModeToInternal(txCfg.SignModeHandler().DefaultMode())
		if err != nil {
			return err
		}
	}

	signerData := authsigning.SignerData{
		ChainID:       chainID,
		AccountNumber: uint64(accNum), // txf.AccountNumber(),
		Sequence:      uint64(accSeq), // txf.Sequence(),
		PubKey:        gnarkPub,
		Address:       sdk.AccAddress(gnarkPub.Address()).String(),
	}

	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: nil,
	}
	sig := signing.SignatureV2{
		PubKey:   gnarkPub,
		Data:     &sigData,
		Sequence: uint64(accSeq),
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
		clientCtx.CmdContext, txCfg.SignModeHandler(), signMode, signerData, txBuilder.GetTx())
	if err != nil {
		return err
	}

	// sign with the hidden key and get the hashed msg
	msgToSign, signatureBytes := gnark.SignMsg(privKey, txSignBytes)

	// prepare the witness for zk proof
	privateWitness, publicWitness := gnark.PrepareWitness(msgToSign, signatureBytes)
	privWitnessBytes, err := privateWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}
	pubWitnessBytes, err := publicWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// produce proof
	proofBytes, err := gnarkPriv.Sign(privWitnessBytes)
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
	sigData = signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: gnarkSigBytes,
	}

	sigV2 := signing.SignatureV2{
		PubKey:   gnarkPub,
		Data:     &sigData,
		Sequence: uint64(accSeq),
	}

	// End tx.SignWithPrivKey
	//----------------------

	err = txBuilder.SetSignatures(sigV2)
	if err != nil {
		return nil
	}

	// set output
	closeFunc, err := setOutputFile(cmd)
	if err != nil {
		return err
	}

	defer closeFunc()
	clientCtx.WithOutput(cmd.OutOrStdout())

	var jsonBytes []byte
	printSignatureOnly := false
	jsonBytes, err = marshalSignatureJSON(txCfg, txBuilder, printSignatureOnly)
	if err != nil {
		return err
	}

	cmd.Printf("%s\n", jsonBytes)

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

func setOutputFile(cmd *cobra.Command) (func(), error) {
	outputDoc, _ := cmd.Flags().GetString(flags.FlagOutputDocument)
	if outputDoc == "" {
		return func() {}, nil
	}

	fp, err := os.OpenFile(outputDoc, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return func() {}, err
	}

	cmd.SetOut(fp)

	return func() { fp.Close() }, nil
}

var tempDir = func() string {
	dir, err := os.MkdirTemp("", "simapp")
	if err != nil {
		dir = simapp.DefaultNodeHome
	}
	defer os.RemoveAll(dir)

	return dir
}
