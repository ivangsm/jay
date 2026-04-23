// jay-config — utility for converting between YAML and .env formats and
// validating jay YAML configs.
//
// Usage:
//
//	jay-config yaml-to-env --input config.yml [--output .env]
//	jay-config env-to-yaml --input .env       [--output config.yml]
//	jay-config validate    --input config.yml
//
// If --output is omitted, writes to stdout.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 1
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "yaml-to-env":
		if err := runYAMLToEnv(rest, stdout, stderr); err != nil {
			_, _ = fmt.Fprintf(stderr, "jay-config: %v\n", err)
			return 1
		}
		return 0
	case "env-to-yaml":
		if err := runEnvToYAML(rest, stdout, stderr); err != nil {
			_, _ = fmt.Fprintf(stderr, "jay-config: %v\n", err)
			return 1
		}
		return 0
	case "validate":
		return runValidate(rest, stdout, stderr)
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "jay-config: unknown subcommand: %s\n\n", cmd)
		usage(stderr)
		return 1
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `jay-config — convert between YAML and .env and validate jay configs

Usage:
  jay-config yaml-to-env --input config.yml [--output .env]
  jay-config env-to-yaml --input .env       [--output config.yml]
  jay-config validate    --input config.yml

If --output is omitted, output is written to stdout.`)
}

func parseIO(args []string) (input, output string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input", "-i":
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("flag %s requires a value", args[i])
			}
			input = args[i+1]
			i++
		case "--output", "-o":
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("flag %s requires a value", args[i])
			}
			output = args[i+1]
			i++
		default:
			return "", "", fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	if input == "" {
		return "", "", fmt.Errorf("--input is required")
	}
	return input, output, nil
}

func openOutput(path string, stdout io.Writer) (io.Writer, func() error, error) {
	if path == "" {
		return stdout, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
