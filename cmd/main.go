/*
Copyright 2023, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"fmt"
	"strings"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/plugin"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

const (
	argNamePrivateKeyFile  = "privateKeyFile"
	argNamePrivateKeyFiles = "privateKeyFiles"
	argNamePublicKeyFile   = "publicKeyFile"
	argNamePaas            = "paas"
	argNameDataFileKey     = "dataFile"
	argNameOutputFormat    = "outputFormat"
	argNameSecretName      = "secretName"
)

var debug bool

// requireSubcommand returns an error if no sub command is provided
// This was copied from podman: `github.com/containers/podman/cmd/podman/validate/args.go
// Some small style changes to match skopeo were applied, but try to apply any
// bugfixes there first.
func requireSubcommand(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		arg := args[0]
		suggestions := cmd.SuggestionsFor(arg)
		if len(suggestions) == 0 {
			return fmt.Errorf(
				"unrecognized command `%[1]s %[2]s`\nTry '%[1]s --help' for more information",
				cmd.CommandPath(),
				arg,
			)
		}

		return fmt.Errorf(
			// revive:disable-next-line
			"unrecognized command `%[1]s %[2]s`\n\nDid you mean this?\n\t%[3]s\n\nTry '%[1]s --help' for more information",
			cmd.CommandPath(),
			arg,
			strings.Join(suggestions, "\n\t"),
		)
	}

	return fmt.Errorf("missing command '%[1]s COMMAND'\nTry '%[1]s --help' for more information", cmd.CommandPath())
}

// createApp returns a cobra.Command, and the underlying globalOptions object, to be run or tested.
func createApp() *cobra.Command {
	configFlags := genericclioptions.NewConfigFlags(true)
	rootCommand := &cobra.Command{
		Use:              "kubectl-paas",
		Long:             "CLI tool for managing Paas resources",
		RunE:             requireSubcommand,
		SilenceUsage:     true,
		SilenceErrors:    true,
		TraverseChildren: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return plugin.SetupKubernetesClient(configFlags)
		},
	}
	configFlags.AddFlags(rootCommand.PersistentFlags())
	rootCommand.Version = version.Version

	rootCommand.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug output")
	rootCommand.AddCommand(
		migrateCmd(),
		decryptCmd(),
		encryptCmd(),
		reencryptCmd(),
		checkPaasCmd(),
		generateCmd(),
	)
	return rootCommand
}

func main() {
	rootCmd := createApp()
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}
