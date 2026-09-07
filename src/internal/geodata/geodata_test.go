package geodata

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstalledAndPath(t *testing.T) {
	dir := t.TempDir()
	assert.False(t, Geosite.Installed(dir), "nothing installed yet")
	assert.Equal(t, filepath.Join(dir, "geosite.dat"), Geosite.Path(dir))
	assert.Equal(t, filepath.Join(dir, "geoip.dat"), GeoIP.Path(dir))

	require.NoError(t, os.WriteFile(Geosite.Path(dir), []byte("data"), 0o600))
	assert.True(t, Geosite.Installed(dir))
	assert.False(t, GeoIP.Installed(dir), "geoip is independent")

	// An empty file does not count as installed.
	require.NoError(t, os.WriteFile(Geosite.Path(dir), nil, 0o600))
	assert.False(t, Geosite.Installed(dir))
}

func TestMetaIsPerAsset(t *testing.T) {
	dir := t.TempDir()
	assert.Equal(t, filepath.Join(dir, "geosite.dat.meta.json"), Geosite.metaPath(dir))
	assert.Equal(t, filepath.Join(dir, "geoip.dat.meta.json"), GeoIP.metaPath(dir))
}

func TestParseSumFile(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := parseSumFile(digest + "  geosite.dat\n")
	require.NoError(t, err)
	assert.Equal(t, digest, got)

	got, err = parseSumFile("# header\n" + digest + " *geoip.dat")
	require.NoError(t, err)
	assert.Equal(t, digest, got)

	_, err = parseSumFile("not a sum\n")
	assert.Error(t, err)
}

func TestURLEnvOverride(t *testing.T) {
	t.Setenv("DECENZED_GEOSITE_URL", "https://example.com/my.dat")
	assert.Equal(t, "https://example.com/my.dat", Geosite.URL())
	t.Setenv("DECENZED_GEOSITE_URL", "")
	assert.Equal(t, Geosite.defaultURL, Geosite.URL())

	t.Setenv("DECENZED_GEOIP_URL", "https://example.com/ip.dat")
	assert.Equal(t, "https://example.com/ip.dat", GeoIP.URL())
}
