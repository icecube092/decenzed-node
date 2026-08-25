package xrayrt

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
			"settings": map[string]any{"udp": false},
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
