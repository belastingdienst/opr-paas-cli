/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"errors"
	"os"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/plugin"
	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/types"
)

// generateCmd generates a new private and public key pair and stores them in the
// specified files.
func generateCmd() *cobra.Command {
	var publicKeyFile string
	var privateKeyFile string
	var outputFormat string
	var secretName string

	cmd := &cobra.Command{
		Use:   "generate [command options]",
		Short: "generate a new private and public key and store them in files",
		Long:  `generate a new private and public key and store them in files`,
		RunE: func(command *cobra.Command, args []string) error {
			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}
			var pks = crypt.PrivateKeys{}
			var oKey *types.NamespacedName
			format, err := paasfile.FormatFromString(outputFormat)
			if err != nil {
				return err
			}
			if secretName != "" {
				oKey = &types.NamespacedName{
					Name:      secretName,
					Namespace: plugin.Namespace,
				}
			}
			secret, err := plugin.GetPaasSecret(command.Context(), oKey)
			if err != nil {
				if outputFormat != "" && secret == nil {
					return err
				}
			}
			if pks, err = crypt.NewPrivateKeysFromSecretData(secret.Data); err != nil {
				return err
			}
			if format == paasfile.DefaultFormat {
				if privateKeyFile == "" || publicKeyFile == "" {
					return errors.New("privateKeyFile or publicKeyFile not specified")
				}
			}
			if format == paasfile.RawFormat {
				if privateKeyFile == "" {
					priv, err := os.CreateTemp("", "private")
					if err != nil {
						return err
					}
					defer priv.Close()
					privateKeyFile = priv.Name()
				}
				if publicKeyFile == "" {
					pub, err := os.CreateTemp("", "private")
					if err != nil {
						return err
					}
					defer pub.Close()
					publicKeyFile = pub.Name()
				}
			}
			pk, err := crypt.GeneratePrivateKey()
			if err != nil {
				return err
			}
			if err = pk.WritePrivateKey(privateKeyFile); err != nil {
				return err
			}
			if err = pk.WritePublicKey(publicKeyFile); err != nil {
				return err
			}
			pks["current"] = pk
			pks[pk.GetID()] = pk
			secret.Data = pks.AsSecretData()
			plugin.Print(secret, format, os.Stdout)
			return nil
		},
		Example: `kubectl-paas generate --publicKeyFile "/tmp/pub" --privateKeyFile "/tmp/priv"`,
	}

	flags := cmd.Flags()
	flags.StringVarP(&publicKeyFile, argNamePublicKeyFile, "P", "", "The file to write the public key to")
	flags.StringVarP(&privateKeyFile, argNamePrivateKeyFile, "p", "", "The file to write the private key to")
	flags.StringVarP(&outputFormat, argNameOutputFormat, "o", "",
		"The output format (leave empty not to print to stdout)")
	flags.StringVarP(&secretName, argNameSecretName, "S", "",
		"The name of the secret (leave empty to use from PaasConfig)")

	if err := viper.BindPFlag(argNamePublicKeyFile, flags.Lookup(argNamePublicKeyFile)); err != nil {
		logrus.Errorf("key binding for publicKeyFile failed: %v", err)
	}
	if err := viper.BindPFlag(argNamePrivateKeyFile, flags.Lookup(argNamePrivateKeyFile)); err != nil {
		logrus.Errorf("key binding for privateKeyFile failed: %v", err)
	}
	if err := viper.BindEnv(argNamePublicKeyFile, "PAAS_PUBLIC_KEY_PATH"); err != nil {
		logrus.Errorf("paas public key binding failed: %v", err)
	}
	if err := viper.BindEnv(argNamePrivateKeyFile, "PAAS_PRIVATE_KEY_PATH"); err != nil {
		logrus.Errorf("paas private key binding failed: %v", err)
	}

	return cmd
}
