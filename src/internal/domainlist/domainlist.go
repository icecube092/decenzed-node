// Package domainlist merges the root-managed base allow-lists with the
// operator's local overrides into the effective routing policy (NODE-CLI
// "Доменные списки").
//
// Precedence rule: an operator DENY always wins (so an operator can be STRICTER
// than the shipped defaults, controlling their own exit liability); an operator
// ALLOW extends the base. The result feeds the xray config generator.
package domainlist

import "sort"

// Policy is the raw input: the signed base allow-list plus the operator's
// local overrides.
type Policy struct {
	BaseAllow     []string // curated by us, auto-updated + signed by root
	OverrideAllow []string // operator additions
	OverrideDeny  []string // operator removals/blocks (win over allow)
}

// Effective is the resolved policy: what to allow (route to direct) and what to
// deny (route to block).
type Effective struct {
	Allow []string
	Deny  []string
}

// Resolve computes Effective = (BaseAllow ∪ OverrideAllow) \ OverrideDeny, with
// deny taking precedence. Output lists are de-duplicated and sorted for
// deterministic config generation.
func (p Policy) Resolve() Effective {
	deny := toSet(p.OverrideDeny)
	allow := make(map[string]struct{})

	add := func(list []string) {
		for _, d := range list {
			if _, denied := deny[d]; denied {
				continue // deny wins
			}
			allow[d] = struct{}{}
		}
	}
	add(p.BaseAllow)
	add(p.OverrideAllow)

	return Effective{Allow: sortedKeys(allow), Deny: sortedKeys(deny)}
}

func toSet(list []string) map[string]struct{} {
	s := make(map[string]struct{}, len(list))
	for _, d := range list {
		s[d] = struct{}{}
	}
	return s
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
