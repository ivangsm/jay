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
	Effect     string            `json:"effect"`               // "allow" or "deny"
	Actions    []string          `json:"actions"`              // e.g. ["object:get", "object:list"] or ["*"]
	Prefixes   []string          `json:"prefixes"`             // e.g. ["public/", "shared/"], empty = all
	Subjects   []string          `json:"subjects"`             // token IDs or "*" for any authenticated
	Conditions *PolicyConditions `json:"conditions,omitempty"`
}

// PolicyConditions holds optional conditions for a policy statement.
type PolicyConditions struct {
	IPWhitelist []string `json:"ip_whitelist,omitempty"` // CIDR notation
}

// EvaluatePolicy checks policy statements against the request context.
// Returns: explicitly allowed, explicitly denied.
func EvaluatePolicy(policy *BucketPolicy, tokenID, action, objectKey, clientIP string) (allowed, denied bool) {
	if policy == nil {
		return false, false
	}

	for _, stmt := range policy.Statements {
		if !matchesSubject(stmt.Subjects, tokenID) {
			continue
		}
		if !matchesAction(stmt.Actions, action) {
			continue
		}
		if !matchesPrefix(stmt.Prefixes, objectKey) {
			continue
		}
		if stmt.Conditions != nil && !matchesIPCondition(stmt.Conditions.IPWhitelist, clientIP) {
			continue
		}

		switch strings.ToLower(stmt.Effect) {
		case "deny":
			denied = true
		case "allow":
			allowed = true
		}
	}

	// Deny takes precedence over allow.
	if denied {
		allowed = false
	}
	return allowed, denied
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

func matchesIPCondition(cidrs []string, clientIP string) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
