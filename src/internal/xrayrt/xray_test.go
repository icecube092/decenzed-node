package xrayrt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"decenzed/node_app/internal/realitykeys"
	"decenzed/node_app/internal/xraygen"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Boots a real embedded xray-core with a minimal socks inbound, reads stats,
// and shuts down — verifying the core.New/Start/Close/GetFeature(stats) wiring.
func TestXrayStartStopStats(t *testing.T) {
	port := freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
			"settings": map[string]any{
				"clients": []any{map[string]any{"method": "chacha20-ietf-poly1305", "password": "u1", "email": "u1"}},
				"network": "tcp",
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
		"stats":     map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
	}
	data, _ := json.Marshal(cfg)

	rt := NewXray()
	require.NoError(t, rt.Start(context.Background(), data), "embedded xray must start")
	defer rt.Stop()

	snap, err := rt.Stats()
	require.NoError(t, err)
	assert.Empty(t, snap, "no tracked users -> empty stats")

	require.NoError(t, rt.Stop())
	require.NoError(t, rt.Stop(), "double stop is a no-op")
}

// Boots xray with a classic AEAD multi-user Shadowsocks inbound (each client
// carrying its own method+password), verifying the embedded core accepts the
// chacha20-ietf-poly1305 multi-user config the generator emits.
func TestXrayClassicShadowsocksStarts(t *testing.T) {
	port := freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"tag": "ss-in", "listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
			"settings": map[string]any{
				"clients": []any{map[string]any{
					"method": "chacha20-ietf-poly1305", "password": "uuid-1", "email": "uuid-1",
				}},
				"network": "tcp,udp",
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	data, _ := json.Marshal(cfg)

	rt := NewXray()
	require.NoError(t, rt.Start(context.Background(), data), "classic multi-user shadowsocks must start")
	require.NoError(t, rt.Stop())
}

// Verifies the node captures xray-core's own logs: with a sink installed and
// debug on, starting xray produces at least one captured line.
func TestXrayLogCapture(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	rt := NewXray()
	rt.SetLogSink(func(level, text string) {
		mu.Lock()
		lines = append(lines, level+"\t"+text)
		mu.Unlock()
	})
	rt.SetDebug(true)

	port := freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "ss-in", "listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
			"settings": map[string]any{
				"clients": []any{map[string]any{"method": "chacha20-ietf-poly1305", "password": "u1", "email": "u1"}},
				"network": "tcp",
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	data, _ := json.Marshal(cfg)
	require.NoError(t, rt.Start(context.Background(), data))
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, rt.Stop())

	mu.Lock()
	n := len(lines)
	mu.Unlock()
	if n == 0 {
		t.Fatal("no xray log lines were captured — the log handler is not wired up")
	}
	t.Logf("captured %d xray log line(s); first: %q", n, lines[0])
}

// Boots the real generated VLESS+REALITY and Trojan+REALITY inbounds together,
// proving the curated feature imports (features.go) cover every protocol and
// transport we ship — a missing registration would fail here with "unknown type".
func TestXrayVlessTrojanRealityStart(t *testing.T) {
	kp, err := realitykeys.Generate()
	require.NoError(t, err)
	reality := &xraygen.RealitySpec{
		Dest: "www.microsoft.com:443", Names: []string{"www.microsoft.com"},
		PrivKey: kp.Private, ShortIDs: []string{"beef"},
	}
	in := xraygen.Input{
		StatsEnabled: true,
		Inbounds: []xraygen.InboundSpec{
			{Protocol: "vless", Port: freePort(t), ListenAddr: "127.0.0.1",
				Clients: []xraygen.ClientCred{{ID: "uuid-1", Email: "uuid-1"}}, Reality: reality},
			{Protocol: "trojan", Port: freePort(t), ListenAddr: "127.0.0.1",
				Clients: []xraygen.ClientCred{{Password: "uuid-1", Email: "uuid-1"}}, Reality: reality},
		},
	}
	data, err := xraygen.Generate(in).JSON()
	require.NoError(t, err)

	rt := NewXray()
	require.NoError(t, rt.Start(context.Background(), data), "vless/trojan + reality must start")
	require.NoError(t, rt.Stop())
}

// Boots the real generated VLESS+TLS inbound with a website fallback — the main
// production masquerade path — validating the tls transport + fallback wiring
// under the curated feature imports.
func TestXrayVlessTLSFallbackStart(t *testing.T) {
	certPath, keyPath := genCertFiles(t)
	tls := &xraygen.TLSSpec{
		ServerName: "example.com", CertFile: certPath, KeyFile: keyPath,
		FallbackDest: "127.0.0.1:8080",
	}
	in := xraygen.Input{
		Inbounds: []xraygen.InboundSpec{{
			Protocol: "vless", Port: freePort(t), ListenAddr: "127.0.0.1",
			Clients: []xraygen.ClientCred{{ID: "uuid-1", Email: "uuid-1"}}, TLS: tls,
		}},
	}
	data, err := xraygen.Generate(in).JSON()
	require.NoError(t, err)

	rt := NewXray()
	require.NoError(t, rt.Start(context.Background(), data), "vless + tls + fallback must start")
	require.NoError(t, rt.Stop())
}

// genCertFiles writes a throwaway self-signed cert/key pair and returns their
// paths (xray reads certificateFile/keyFile).
func genCertFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

// Boots BOTH Shadowsocks variants at once (classic + SS-2022) to prove their
// inbound tags don't collide — a duplicate tag would stop xray from starting.
func TestXrayBothShadowsocksVariantsStart(t *testing.T) {
	const key16 = "AAAAAAAAAAAAAAAAAAAAAA==" // base64 of 16 bytes (SS-2022 key len)
	p1, p2 := freePort(t), freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{
			map[string]any{
				"tag": "shadowsocks-in", "listen": "127.0.0.1", "port": p1, "protocol": "shadowsocks",
				"settings": map[string]any{
					"clients": []any{map[string]any{"method": "chacha20-ietf-poly1305", "password": "u1", "email": "u1"}},
					"network": "tcp,udp",
				},
			},
			map[string]any{
				"tag": "shadowsocks2022-in", "listen": "127.0.0.1", "port": p2, "protocol": "shadowsocks",
				"settings": map[string]any{
					"method":   "2022-blake3-aes-128-gcm",
					"password": key16,
					"clients":  []any{map[string]any{"password": key16, "email": "u1"}},
					"network":  "tcp,udp",
				},
			},
		},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	data, _ := json.Marshal(cfg)

	rt := NewXray()
	require.NoError(t, rt.Start(context.Background(), data), "both SS inbounds must start (unique tags)")
	require.NoError(t, rt.Stop())
}
