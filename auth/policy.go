package auth

import (
	"net"
	"strings"
)

// BucketPolicy defines prefix-based access rules for a bucket.
type BucketPolicy struct {
	Version    string            `json:"version"`
	Statements []PolicyStatement `json:"statements"`
}

// PolicyStatement is a single allow/deny rule within a bucket policy.
type PolicyStatement struct {
	Effect     string            `json:"effect"`   // "allow" or "deny"
	Actions    []string          `json:"actions"`  // e.g. ["object:get", "object:list"] or ["*"]
	Prefixes   []string          `json:"prefixes"` // e.g. ["public/", "shared/"], empty = all
	Subjects   []string          `json:"subjects"` // token IDs or "*" for any authenticated
	Conditions *PolicyConditions `json:"conditions,omitempty"`
}

// PolicyConditions holds optional conditions for a policy statement.
type PolicyConditions struct {
	IPWhitelist []string     `json:"ip_whitelist,omitempty"` // CIDR notation
	parsedCIDRs []*net.IPNet // pre-parsed from IPWhitelist by Compile()
}

// Compile pre-parses all CIDRs in the policy statements so that
// matchesIPConditionNets can use them without re-parsing on every request.
// Call this after unmarshalling a BucketPolicy.
func (p *BucketPolicy) Compile() {
	if p == nil {
		return
	}
	for i := range p.Statements {
		cond := p.Statements[i].Conditions
		if cond == nil || len(cond.IPWhitelist) == 0 {
			continue
		}
		cond.parsedCIDRs = make([]*net.IPNet, 0, len(cond.IPWhitelist))
		for _, cidr := range cond.IPWhitelist {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			cond.parsedCIDRs = append(cond.parsedCIDRs, network)
		}
	}
}

// EvaluatePolicyDeny checks policy deny statements against the request context.
// Returns true if any deny statement matches (access should be refused).
func EvaluatePolicyDeny(policy *BucketPolicy, tokenID, action, objectKey, clientIP string) bool {
	return matchesEffect(policy, "deny", tokenID, action, objectKey, clientIP)
}

// EvaluatePolicyAllow reports whether an allow statement grants the request.
//
// An allow statement only ever GRANTS. It is consulted by AuthorizeBucketAccess
// for a caller that has no other claim on the bucket — a token belonging to a
// different account — and it is the only way an operator can open a bucket to
// one. It never narrows what the owner may do, and it never beats a deny: deny
// is evaluated afterwards, on the same statement set, and wins.
func EvaluatePolicyAllow(policy *BucketPolicy, tokenID, action, objectKey, clientIP string) bool {
	return matchesEffect(policy, "allow", tokenID, action, objectKey, clientIP)
}

// matchesEffect reports whether any statement with the given effect matches the
// request context. Allow and deny share this so a statement can never be read
// two different ways depending on which evaluator looked at it.
func matchesEffect(policy *BucketPolicy, effect, tokenID, action, objectKey, clientIP string) bool {
	if policy == nil {
		return false
	}

	for _, stmt := range policy.Statements {
		if strings.ToLower(stmt.Effect) != effect {
			continue
		}
		if !matchesSubject(stmt.Subjects, tokenID) {
			continue
		}
		if !matchesAction(stmt.Actions, action) {
			continue
		}
		if !matchesPrefix(stmt.Prefixes, objectKey) {
			continue
		}
		if stmt.Conditions != nil && !matchesIPConditionNets(stmt.Conditions.parsedCIDRs, clientIP) {
			continue
		}
		return true
	}
	return false
}

func matchesSubject(subjects []string, tokenID string) bool {
	for _, s := range subjects {
		if s == "*" || s == tokenID {
			return true
		}
	}
	return false
}

func matchesAction(actions []string, action string) bool {
	for _, a := range actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

func matchesPrefix(prefixes []string, objectKey string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(objectKey, p) {
			return true
		}
	}
	return false
}

func matchesIPConditionNets(networks []*net.IPNet, clientIP string) bool {
	if len(networks) == 0 {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
