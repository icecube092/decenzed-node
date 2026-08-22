package domainlist

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDenyOverridesBaseAllow(t *testing.T) {
	e := Policy{BaseAllow: []string{"a.com", "b.com"}, OverrideDeny: []string{"a.com"}}.Resolve()
	assert.Equal(t, []string{"b.com"}, e.Allow, "deny wins over base allow")
	assert.Equal(t, []string{"a.com"}, e.Deny)
}

func TestOverrideAllowExtends(t *testing.T) {
	e := Policy{BaseAllow: []string{"a.com"}, OverrideAllow: []string{"c.com"}}.Resolve()
	assert.Equal(t, []string{"a.com", "c.com"}, e.Allow)
}

func TestDedupAndSort(t *testing.T) {
	e := Policy{BaseAllow: []string{"b.com", "a.com", "a.com"}, OverrideAllow: []string{"b.com"}}.Resolve()
	assert.Equal(t, []string{"a.com", "b.com"}, e.Allow)
}
