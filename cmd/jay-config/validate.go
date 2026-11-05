package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func runValidate(args []string, stdout, stderr io.Writer) int {
	input, _, err := parseIOValidate(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "jay-config: %v\n", err)
		return 1
	}

	raw, err := os.ReadFile(input)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "jay-config: read %s: %v\n", input, err)
		return 1
	}

	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		_, _ = fmt.Fprintf(stderr, "jay-config: parse YAML %s: %v\n", input, err)
		return 1
	}

	errs, warns := validateDocument(&root, input)

	for _, w := range warns {
		_, _ = fmt.Fprintf(stderr, "warning: %s\n", w)
	}

	if len(errs) > 0 {
		for _, e := range errs {
			_, _ = fmt.Fprintf(stderr, "error: %s\n", e)
		}
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "OK: %s is valid\n", input)
	return 0
}

func parseIOValidate(args []string) (input, output string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input", "-i":
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("flag %s requires a value", args[i])
			}
			input = args[i+1]
			i++
		default:
			return "", "", fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	if input == "" {
		return "", "", errors.New("--input is required")
	}
	return input, "", nil
}

func validateDocument(root *yaml.Node, path string) (errs []string, warns []string) {
	if root.Kind == 0 || len(root.Content) == 0 {
		return []string{path + ": empty document"}, nil
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return []string{locLabel(path, top) + ": top-level must be a mapping"}, nil
	}

	fields := map[string]*yaml.Node{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		k := top.Content[i]
		v := top.Content[i+1]
		if !topLevelKnownKeys[k.Value] {
			warns = append(warns, fmt.Sprintf("%s: unknown top-level key %q", locLabel(path, k), k.Value))
			continue
		}
		fields[k.Value] = v
	}

	validateTypes(path, fields, &errs)
	validateSecrets(path, fields, &errs)
	validateSeedToken(path, fields, top, &errs)
	validateScrub(path, fields, &errs, &warns)
	validateRate(path, fields, &errs)
	validateNative(path, fields, &errs)
	validateMetrics(path, fields, &errs, &warns)
	validateLogLevel(path, fields, &errs)
	return errs, warns
}

func locLabel(path string, node *yaml.Node) string {
	if node == nil || node.Line == 0 {
		return path
	}
	return fmt.Sprintf("%s:%d:%d", path, node.Line, node.Column)
}

func validateTypes(path string, fields map[string]*yaml.Node, errs *[]string) {
	for _, spec := range fieldSpecs {
		if len(spec.yamlPath) == 1 {
			n, ok := fields[spec.yamlPath[0]]
			if !ok {
				continue
			}
			if !checkScalarType(n, spec.kind) {
				*errs = append(*errs, fmt.Sprintf("%s: expected %s for %s", locLabel(path, n), typeName(spec.kind), spec.yamlKey))
			}
			continue
		}
		parent, ok := fields[spec.yamlPath[0]]
		if !ok {
			continue
		}
		if parent.Kind != yaml.MappingNode {
			*errs = append(*errs, fmt.Sprintf("%s: %s must be a mapping", locLabel(path, parent), spec.yamlPath[0]))
			continue
		}
		child := findChild(parent, spec.yamlPath[1])
		if child == nil {
			continue
		}
		if !checkScalarType(child, spec.kind) {
			*errs = append(*errs, fmt.Sprintf("%s: expected %s for %s", locLabel(path, child), typeName(spec.kind), spec.yamlKey))
		}
	}
}

func typeName(k fieldType) string {
	switch k {
	case typeString:
		return "string"
	case typeInt:
		return "int"
	case typeFloat:
		return "float"
	case typeBool:
		return "bool"
	}
	return "unknown"
}

// checkScalarType reports whether the server's loader would accept n for kind.
// It mirrors toBool, toInt64 and toFloat64 in cmd/jay: a quoted scalar such as
// "true" or "5" reaches the server as a string and is parsed with strconv, and
// a whole float is a valid integer. A validator stricter than the server
// rejects configs that run, which teaches people to stop running it.
func checkScalarType(n *yaml.Node, kind fieldType) bool {
	if n.Kind != yaml.ScalarNode {
		return false
	}
	if isInterpolation(n.Value) {
		return true
	}
	switch kind {
	case typeString:
		return true
	case typeBool:
		switch n.Tag {
		case "!!bool", "":
			return true
		case "!!str":
			_, err := strconv.ParseBool(n.Value)
			return err == nil
		}
	case typeInt:
		switch n.Tag {
		case "!!int":
			return true
		case "":
			return isIntLiteral(n.Value)
		case "!!str":
			_, err := strconv.ParseInt(n.Value, 10, 64)
			return err == nil
		case "!!float":
			f, err := strconv.ParseFloat(n.Value, 64)
			return err == nil && f == math.Trunc(f) && !math.IsInf(f, 0)
		}
	case typeFloat:
		switch n.Tag {
		case "!!int", "!!float":
			return true
		case "":
			return isIntLiteral(n.Value) || isFloatLiteral(n.Value)
		case "!!str":
			_, err := strconv.ParseFloat(n.Value, 64)
			return err == nil
		}
	}
	return false
}

func isIntLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i = 1
		if len(s) == 1 {
			return false
		}
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isFloatLiteral(s string) bool {
	if s == "" {
		return false
	}
	seenDot := false
	seenDigit := false
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i = 1
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if seenDot {
				return false
			}
			seenDot = true
		} else if c >= '0' && c <= '9' {
			seenDigit = true
		} else {
			return false
		}
	}
	return seenDigit
}

func isInterpolation(s string) bool {
	return strings.Contains(s, "${")
}

func findChild(mapping *yaml.Node, key string) *yaml.Node {
	if mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func validateSecrets(path string, fields map[string]*yaml.Node, errs *[]string) {
	for _, name := range []string{"admin_token", "signing_secret"} {
		n, ok := fields[name]
		if !ok {
			*errs = append(*errs, fmt.Sprintf("%s: missing required field %s", path, name))
			continue
		}
		if n.Kind != yaml.ScalarNode {
			continue
		}
		v := n.Value
		if isInterpolation(v) {
			continue
		}
		if len(v) < 32 {
			*errs = append(*errs, fmt.Sprintf("%s: %s must be >= 32 characters (got %d)", locLabel(path, n), name, len(v)))
		}
	}
}

func validateSeedToken(path string, fields map[string]*yaml.Node, top *yaml.Node, errs *[]string) {
	st, ok := fields["seed_token"]
	if !ok {
		return
	}
	if st.Kind != yaml.MappingNode {
		*errs = append(*errs, locLabel(path, st)+": seed_token must be a mapping")
		return
	}
	present := map[string]bool{}
	for _, k := range []string{"account", "id", "secret"} {
		if findChild(st, k) != nil {
			present[k] = true
		}
	}
	n := len(present)
	if n != 0 && n != 3 {
		missing := []string{}
		for _, k := range []string{"account", "id", "secret"} {
			if !present[k] {
				missing = append(missing, k)
			}
		}
		*errs = append(*errs, fmt.Sprintf("%s: seed_token is partial — missing: %s (all three must be present or all three absent)", locLabel(path, st), strings.Join(missing, ", ")))
	}
}

func validateScrub(path string, fields map[string]*yaml.Node, errs *[]string, warns *[]string) {
	scrub, ok := fields["scrub"]
	if !ok {
		return
	}
	if scrub.Kind != yaml.MappingNode {
		*errs = append(*errs, locLabel(path, scrub)+": scrub must be a mapping")
		return
	}

	for i := 0; i+1 < len(scrub.Content); i += 2 {
		k := scrub.Content[i]
		if !nestedKnownKeys["scrub"][k.Value] {
			*warns = append(*warns, fmt.Sprintf("%s: unknown scrub key %q", locLabel(path, k), k.Value))
		}
	}

	if n := findChild(scrub, "interval_hours"); n != nil && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i <= 0 {
			*errs = append(*errs, locLabel(path, n)+": scrub.interval_hours must be > 0")
		}
	}
	if n := findChild(scrub, "max_per_run"); n != nil && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i <= 0 {
			*errs = append(*errs, locLabel(path, n)+": scrub.max_per_run must be > 0")
		}
	}
	if n := findChild(scrub, "bytes_per_sec"); n != nil && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i < 0 {
			*errs = append(*errs, locLabel(path, n)+": scrub.bytes_per_sec must be >= 0")
		}
	}
}

func validateRate(path string, fields map[string]*yaml.Node, errs *[]string) {
	if n, ok := fields["rate_limit"]; ok && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if f, ok := parseFloat(n.Value); ok && f < 0 {
			*errs = append(*errs, locLabel(path, n)+": rate_limit must be >= 0")
		}
	}
	if n, ok := fields["rate_burst"]; ok && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i < 0 {
			*errs = append(*errs, locLabel(path, n)+": rate_burst must be >= 0")
		}
	}
}

// validateNative checks the native listener's limits against what the server
// accepts: a connection cap of zero would refuse every client, and a negative
// byte rate means nothing.
func validateNative(path string, fields map[string]*yaml.Node, errs *[]string) {
	if n, ok := fields["native_max_conns"]; ok && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i <= 0 {
			*errs = append(*errs, locLabel(path, n)+": native_max_conns must be > 0")
		}
	}
	if n, ok := fields["native_token_bytes_per_sec"]; ok && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i < 0 {
			*errs = append(*errs, locLabel(path, n)+": native_token_bytes_per_sec must be >= 0")
		}
	}
}

// validateMetrics applies the server's checkMetricsAccess to the file: the
// metrics token is a secret with the admin token's floor, it must not BE the
// admin token, and it cannot be combined with public scraping. A value that is
// still an ${VAR} interpolation is not judged — only the running server sees
// what it resolves to.
func validateMetrics(path string, fields map[string]*yaml.Node, errs, warns *[]string) {
	section, ok := fields["metrics"]
	if !ok || section.Kind != yaml.MappingNode {
		return // a non-mapping is already reported by validateTypes
	}
	for i := 0; i+1 < len(section.Content); i += 2 {
		k := section.Content[i]
		if !nestedKnownKeys["metrics"][k.Value] {
			*warns = append(*warns, fmt.Sprintf("%s: unknown metrics key %q", locLabel(path, k), k.Value))
		}
	}

	token := literalScalar(findChild(section, "token"))
	public := literalScalar(findChild(section, "public"))
	isPublic := false
	if public != nil {
		// The server reads the value with strconv.ParseBool; so does this.
		isPublic, _ = strconv.ParseBool(public.Value)
	}

	if token != nil && token.Value != "" {
		if isPublic {
			*errs = append(*errs, locLabel(path, token)+
				": metrics.token and metrics.public: true are mutually exclusive")
		}
		if len(token.Value) < 32 {
			*errs = append(*errs, fmt.Sprintf("%s: metrics.token must be >= 32 characters when set (got %d)",
				locLabel(path, token), len(token.Value)))
		}
		if admin := literalScalar(fields["admin_token"]); admin != nil && admin.Value == token.Value {
			*errs = append(*errs, locLabel(path, token)+
				": metrics.token must differ from admin_token, or every scraper holds the admin credential")
		}
	}
	if isPublic {
		*warns = append(*warns, locLabel(path, public)+
			": metrics.public is true: GET /metrics answers without authentication")
	}
}

// literalScalar returns n when it is a scalar whose value is written out in
// the file, and nil for anything else — absent, a mapping, or an ${VAR}
// interpolation that only resolves at runtime.
func literalScalar(n *yaml.Node) *yaml.Node {
	if n == nil || n.Kind != yaml.ScalarNode || isInterpolation(n.Value) {
		return nil
	}
	return n
}

func validateLogLevel(path string, fields map[string]*yaml.Node, errs *[]string) {
	n, ok := fields["log_level"]
	if !ok {
		return
	}
	if n.Kind != yaml.ScalarNode {
		return
	}
	if isInterpolation(n.Value) {
		return
	}
	switch n.Value {
	case "debug", "info", "warn", "error":
		return
	default:
		*errs = append(*errs, fmt.Sprintf("%s: log_level must be one of debug|info|warn|error, got %q", locLabel(path, n), n.Value))
	}
}

func parseInt(s string) (int64, bool) {
	if !isIntLiteral(s) {
		return 0, false
	}
	var n int64
	sign := int64(1)
	i := 0
	switch s[0] {
	case '-':
		sign = -1
		i = 1
	case '+':
		i = 1
	}
	for ; i < len(s); i++ {
		n = n*10 + int64(s[i]-'0')
	}
	return sign * n, true
}

func parseFloat(s string) (float64, bool) {
	if !isIntLiteral(s) && !isFloatLiteral(s) {
		return 0, false
	}
	var whole, frac float64
	var divisor float64 = 1
	sign := 1.0
	seenDot := false
	i := 0
	switch s[0] {
	case '-':
		sign = -1
		i = 1
	case '+':
		i = 1
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			seenDot = true
			continue
		}
		d := float64(c - '0')
		if seenDot {
			divisor *= 10
			frac += d / divisor
		} else {
			whole = whole*10 + d
		}
	}
	return sign * (whole + frac), true
}
