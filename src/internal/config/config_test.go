package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := Default()
	c.PublicIP = "203.0.113.7"
	c.MonthlyLimitBytes = 123456
	c.DomainDeny = []string{"bad.com"}
	c.Clients = []Client{{UUID: "u-1", Name: "me"}, {UUID: "u-2", Name: "friend"}}

	require.NoError(t, Save(path, c))
	got, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, c.PublicIP, got.PublicIP)
	assert.Equal(t, c.MonthlyLimitBytes, got.MonthlyLimitBytes)
	assert.Equal(t, []string{"bad.com"}, got.DomainDeny)
	assert.Equal(t, []string{"u-1", "u-2"}, got.UUIDs())
}

func TestBlocksBittorrent(t *testing.T) {
	c := Default()
	assert.True(t, c.BlocksBittorrent(), "default blocks bittorrent")
	c.BlockProtocols = nil
	assert.False(t, c.BlocksBittorrent())
}
