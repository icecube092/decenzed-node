package realitykeys

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestGenerateProducesValidX25519(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if kp.Private == "" || kp.Public == "" || kp.Private == kp.Public {
		t.Fatalf("bad keypair: %+v", kp)
	}
	for name, v := range map[string]string{"priv": kp.Private, "pub": kp.Public} {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("%s not base64 raw-url: %v", name, err)
		}
		if len(b) != 32 {
			t.Fatalf("%s length = %d, want 32", name, len(b))
		}
	}
}

func TestShortID(t *testing.T) {
	id, err := ShortID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 8 {
		t.Fatalf("short id %q length = %d, want 8", id, len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("short id not hex: %v", err)
	}
}
