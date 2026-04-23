package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func runValidate(args []string, stdout, stderr io.Writer) int {
	input, _, err := parseIOValidate(args)
	if err != nil {
		fmt.Fprintf(stderr, "jay-config: %v\n", err)
		return 1
	}

	raw, err := os.ReadFile(input)
	if err != nil {
		fmt.Fprintf(stderr, "jay-config: read %s: %v\n", input, err)
		return 1
	}

	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		fmt.Fprintf(stderr, "jay-config: parse YAML %s: %v\n", input, err)
		return 1
	}

	errs, warns := validateDocument(&root, input)

	for _, w := range warns {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}

	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(stderr, "error: %s\n", e)
		}
		return 1
	}

	fmt.Fprintf(stdout, "OK: %s is valid\n", input)
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
		return "", "", fmt.Errorf("--input is required")
	}
	return input, "", nil
}

func validateDocument(root *yaml.Node, path string) (errs []string, warns []string) {
	if root.Kind == 0 || len(root.Content) == 0 {
		errs = append(errs, fmt.Sprintf("%s: empty document", path))
		return
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		errs = append(errs, locLabel(path, top)+": top-level must be a mapping")
		return
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
	validateLogLevel(path, fields, &errs)
	return
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
		return n.Tag == "!!bool" || n.Tag == ""
	case typeInt:
		return n.Tag == "!!int" || (n.Tag == "" && isIntLiteral(n.Value))
	case typeFloat:
		return n.Tag == "!!int" || n.Tag == "!!float" || (n.Tag == "" && (isIntLiteral(n.Value) || isFloatLiteral(n.Value)))
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
		*errs = append(*errs, fmt.Sprintf("%s: seed_token must be a mapping", locLabel(path, st)))
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
		*errs = append(*errs, fmt.Sprintf("%s: scrub must be a mapping", locLabel(path, scrub)))
		return
	}

	for i := 0; i+1 < len(scrub.Content); i += 2 {
		k := scrub.Content[i]
		if !scrubKnownKeys[k.Value] {
			*warns = append(*warns, fmt.Sprintf("%s: unknown scrub key %q", locLabel(path, k), k.Value))
		}
	}

	if n := findChild(scrub, "sample_rate"); n != nil && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if f, ok := parseFloat(n.Value); ok {
			if !(f > 0.0 && f <= 1.0) {
				*errs = append(*errs, fmt.Sprintf("%s: scrub.sample_rate must be in (0.0, 1.0], got %v", locLabel(path, n), f))
			}
		}
	}
	if n := findChild(scrub, "interval_hours"); n != nil && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i <= 0 {
			*errs = append(*errs, fmt.Sprintf("%s: scrub.interval_hours must be > 0", locLabel(path, n)))
		}
	}
	if n := findChild(scrub, "max_per_run"); n != nil && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i <= 0 {
			*errs = append(*errs, fmt.Sprintf("%s: scrub.max_per_run must be > 0", locLabel(path, n)))
		}
	}
	if n := findChild(scrub, "bytes_per_sec"); n != nil && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i < 0 {
			*errs = append(*errs, fmt.Sprintf("%s: scrub.bytes_per_sec must be >= 0", locLabel(path, n)))
		}
	}
}

func validateRate(path string, fields map[string]*yaml.Node, errs *[]string) {
	if n, ok := fields["rate_limit"]; ok && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if f, ok := parseFloat(n.Value); ok && f < 0 {
			*errs = append(*errs, fmt.Sprintf("%s: rate_limit must be >= 0", locLabel(path, n)))
		}
	}
	if n, ok := fields["rate_burst"]; ok && n.Kind == yaml.ScalarNode && !isInterpolation(n.Value) {
		if i, ok := parseInt(n.Value); ok && i < 0 {
			*errs = append(*errs, fmt.Sprintf("%s: rate_burst must be >= 0", locLabel(path, n)))
		}
	}
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
