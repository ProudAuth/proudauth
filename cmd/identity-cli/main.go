// Command identity-cli is the operator and administrator command-line tool.
//
// Operator commands run locally against the database and key material (the
// operator-only trust class, §25.2): migrate, realm, bootstrap, doctor,
// verify-audit, support-bundle, restore-begin, restore-reconcile,
// generate-root-key.
//
// Administrative commands call the HTTP API with a token obtained through
// "login" (headless interactive login with MFA, or the device flow) and are
// subject to the same permission checks and audit as any other API client.
package main

import (
	"fmt"
	"os"
	"sort"
)

// version is the release this binary was built from, set at build time with
// -ldflags "-X main.version=<tag>" (Dockerfile, release workflow, offline
// bundle). It is reported in support bundles (OPS-010).
var version = "dev"

type command struct {
	summary string
	run     func(args []string) error
}

var commands = map[string]command{}

func register(name, summary string, run func([]string) error) {
	commands[name] = command{summary: summary, run: run}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: identity-cli <command> [flags]\n\ncommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-22s %s\n", n, commands[n].summary)
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, ok := commands[os.Args[1]]
	if !ok {
		usage()
		os.Exit(2)
	}
	if err := cmd.run(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
