package fairplay

import "encoding/hex"

func mustHexFP(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
