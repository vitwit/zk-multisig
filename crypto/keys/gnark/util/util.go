package gnarkutil

import (
	// hash to curve
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// hash the msg to the curve using fr.Hash
func HashMsg(msg []byte) []byte {
	elems, err := fr.Hash(msg, nil, 1)
	if err != nil {
		panic(err)
	}
	elb := elems[0].Bytes()
	msgToSign := elb[:]
	return msgToSign
}
