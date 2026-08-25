//go:build staging

package acme

// StagingBuild is true in binaries built with `-tags staging`; see env_prod.go.
const StagingBuild = true
