// Command juggernaut is the operator CLI: validate and inspect juggernaut.yaml,
// print the JSON Schema, and (later milestones) migrate configs and log in to
// the admin UI.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ExitOnError)
		file := fs.String("f", "juggernaut.yaml", "config file")
		_ = fs.Parse(os.Args[2:])
		l, err := config.LoadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			os.Exit(1)
		}
		fmt.Printf("OK %s (hash %s): %d server types, %d groups\n", *file, l.Hash, len(l.Config.Servers), len(l.Config.Authorization.Groups))
	case "render":
		fs := flag.NewFlagSet("render", flag.ExitOnError)
		file := fs.String("f", "juggernaut.yaml", "config file")
		_ = fs.Parse(os.Args[2:])
		l, err := config.LoadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			os.Exit(1)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(l.Config)
	case "schema":
		_, _ = os.Stdout.Write(config.SchemaJSON())
	case "version":
		fmt.Println(version.Version)
	case "config":
		fmt.Fprintln(os.Stderr, "config migrate: nothing to migrate for", config.APIVersion)
	case "admin":
		fmt.Fprintln(os.Stderr, "admin login ships in milestone 3")
		os.Exit(2)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: juggernaut <command>

  validate -f juggernaut.yaml   validate against the schema and semantic rules
  render   -f juggernaut.yaml   print the defaulted config as JSON
  schema                        print the JSON Schema
  config migrate                rewrite an older config version (no-op today)
  admin login                   obtain an admin token for the admin UI (milestone 3)
  version`)
}
