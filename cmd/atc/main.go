package main

import (
	"fmt"
	"os"

	"github.com/concourse/atc/atccmd"
	"github.com/concourse/atc/auth/provider"
	"github.com/jessevdk/go-flags"
)

func main() {
	cmd := &atccmd.ATCCommand{}

	parser := flags.NewParser(cmd, flags.Default)
	parser.NamespaceDelimiter = "-"

	authConfigs := make(provider.AuthConfigs)

	for name, p := range provider.GetProviders() {
		authConfigs[name] = p.AddAuthGroup(parser)
	}

	args, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	cmd.ProviderAuth = authConfigs

	err = cmd.Execute(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
