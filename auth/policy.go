package auth

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/ivangsm/jay/meta"
)

// ErrInvalidPolicy is what ValidatePolicy wraps. Callers map it to a 400: every
// case it covers is something the sender wrote, not something jay failed at.
var ErrInvalidPolicy = errors.New("auth: invalid bucket policy")

// The two effects a statement can carry. matchesEffect lowercases before
// comparing, so the document may spell them in any case.
const (
	effectAllow = "allow"
	effectDeny  = "deny"
)

// ValidatePolicy refuses a document the evaluator could not act on as written.
//
// This runs where the policy ENTERS, not where it is evaluated, and that is the
// whole point: every rule below describes something that silently does nothing
// at evaluation time, which is the worst possible failure for an access-control
// document. A policy that is stored and never matches looks installed —
// `GET /_jay/buckets/{name}` shows it, the operator moves on — and the access it
// was supposed to grant or deny simply never happens.
//
// The three that bite hardest:
//
//   - A misspelt action ("object:read") matches nothing, ever. The deny that
//     was meant to close a prefix leaves it open.
//   - An empty subjects list matches nothing either, because matchesSubject
//     iterates and returns false on an empty slice. The statement is inert.
//   - An unparsable CIDR is worse than inert, and in the dangerous direction:
//     Compile skips the ones that do not parse, and matchesIPConditionNets
//     treats an EMPTY network list as "any IP". So `"ip_whitelist": ["10.0.0/8"]`
//     — one dot short — turns a statement scoped to an internal range into one
//     that matches the entire internet.
func ValidatePolicy(policy *BucketPolicy) error {
	if policy == nil {
		return fmt.Errorf("%w: no document", ErrInvalidPolicy)
	}
	if len(policy.Statements) == 0 {
		return fmt.Errorf("%w: no statements — a policy that grants and denies "+
			"nothing is a no-op; remove the policy instead", ErrInvalidPolicy)
	}
	for i, stmt := range policy.Statements {
		if err := validateStatement(i, stmt); err != nil {
			return err
		}
	}
	return nil
}

func validateStatement(i int, stmt PolicyStatement) error {
	switch strings.ToLower(strings.TrimSpace(stmt.Effect)) {
	case effectAllow, effectDeny:
	default:
		return fmt.Errorf("%w: statement %d: effect must be %q or %q, got %q",
			ErrInvalidPolicy, i, effectAllow, effectDeny, stmt.Effect)
	}

	if len(stmt.Actions) == 0 {
		return fmt.Errorf("%w: statement %d: actions is empty, so the statement "+
			"can never match", ErrInvalidPolicy, i)
	}
	for _, action := range stmt.Actions {
		if action == "*" || slices.Contains(meta.AllActions, action) {
			continue
		}
		return fmt.Errorf("%w: statement %d: %q is not one of %v (or \"*\")",
			ErrInvalidPolicy, i, action, meta.AllActions)
	}

	if len(stmt.Subjects) == 0 {
		return fmt.Errorf("%w: statement %d: subjects is empty, so the statement "+
			"can never match; use [\"*\"] for every authenticated token",
			ErrInvalidPolicy, i)
	}

	if stmt.Conditions == nil {
		return nil
	}
	for _, cidr := range stmt.Conditions.IPWhitelist {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("%w: statement %d: %q is not a CIDR range — an "+
				"unparsable one is dropped and an empty whitelist matches every "+
				"address", ErrInvalidPolicy, i, cidr)
		}
	}
	return nil
}

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
	return matchesEffect(policy, effectDeny, tokenID, action, objectKey, clientIP)
}

// EvaluatePolicyAllow reports whether an allow statement grants the request.
//
// An allow statement only ever GRANTS. It is consulted by AuthorizeBucketAccess
// for a caller that has no other claim on the bucket — a token belonging to a
// different account — and it is the only way an operator can open a bucket to
// one. It never narrows what the owner may do, and it never beats a deny: deny
// is evaluated afterwards, on the same statement set, and wins.
func EvaluatePolicyAllow(policy *BucketPolicy, tokenID, action, objectKey, clientIP string) bool {
	return matchesEffect(policy, effectAllow, tokenID, action, objectKey, clientIP)
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
