/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"github.com/belastingdienst/opr-paas-cli/v2/internal/migrate"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func migrateCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "migrate [command options]",
		Short: "migrate any Paas version (e.a. v1alpha1) to v1alpha2",
		Long: `parse yaml/json files with any version (e.a. v1alpha1) and migrate to the latest version ` +
			`(currently v1alpha2).`,
		RunE: func(command *cobra.Command, args []string) error {
			var files []string
			var err error

			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}

			if files, err = utils.PathToFileList(args); err != nil {
				return err
			}
			f, err := paasfile.FormatFromString(outputFormat)
			if err != nil {
				return err
			}
			return migrate.Migrate(files, f)
		},
		Args:    cobra.MinimumNArgs(1),
		Example: `kubectl-paas migrate [file or dir] ([file or dir]...)`,
	}

	flags := cmd.Flags()
	flags.StringVar(
		&outputFormat,
		argNameOutputFormat,
		"auto",
		"The outputformat for writing a Paas, either yaml (machine formatted), json (machine formatted), "+
			"auto (which will use input format as output, machine formatted) or preserve (which will use the "+
			"input format and preserve the original syntax including for example comments) ",
	)

	if err := viper.BindPFlag(argNameOutputFormat, flags.Lookup(argNameOutputFormat)); err != nil {
		logrus.Errorf("key binding at output step failed: %v", err)
	}
	if err := viper.BindEnv(argNameOutputFormat, "PAAS_OUTPUT_FORMAT"); err != nil {
		logrus.Errorf("key binding at output step failed: %v", err)
	}

	return cmd
}
