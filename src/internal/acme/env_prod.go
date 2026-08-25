//go:build !staging

package acme

// StagingBuild reports whether this binary targets the Let's Encrypt STAGING
// environment. It is false in normal (release) builds; build with `-tags staging`
// to flip it on for testing (staging issues untrusted certs with far higher rate
// limits, so test runs never burn the production quota).
const StagingBuild = false
