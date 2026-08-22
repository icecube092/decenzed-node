// Package realitykeys generates the REALITY X25519 keypair and short ids for a
// node. The PRIVATE key stays on the node (it feeds the xray inbound); the
// PUBLIC key + short id are published to root, which hands them to clients so
// they can complete the REALITY handshake. Encoding matches `xray x25519`
// (base64 raw-url) so the values are drop-in for xray configs.
package realitykeys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// Keypair is a REALITY X25519 keypair, base64-raw-url encoded.
type Keypair struct {
	Private string
	Public  string
}

// Generate returns a fresh REALITY keypair.
func Generate() (Keypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, err
	}
	enc := base64.RawURLEncoding
	return Keypair{
		Private: enc.EncodeToString(priv.Bytes()),
		Public:  enc.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// ShortID returns a random REALITY short id (hex, 8 chars = 4 bytes).
func ShortID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
