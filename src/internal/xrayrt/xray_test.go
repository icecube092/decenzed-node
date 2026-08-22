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
