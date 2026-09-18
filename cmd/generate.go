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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// generateCmd generates a new private and public key pair and stores them in the
// specified files.
func generateCmd() *cobra.Command {
	var publicKeyFile string
	var privateKeyFile string
	var outputFormat string
	var encryptionSecretName string

	cmd := &cobra.Command{
		Use:   "generate [command options]",
		Short: "generate a new private and public key and store them in files",
		Long:  `generate a new private and public key and store them in files`,
		RunE: func(command *cobra.Command, args []string) error {
			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}
			var oKey *types.NamespacedName
			format, err := paasfile.FormatFromString(outputFormat)
			if err != nil {
				return err
			}
			if encryptionSecretName != "" {
				oKey = &types.NamespacedName{
					Name:      encryptionSecretName,
					Namespace: plugin.Namespace,
				}
			}
			secret, err := plugin.GetPaasSecret(command.Context(), oKey)
			if err != nil && secret == nil {
				// No PaasConfig exists or no secret was found. This is expected when
				// bootstrapping a cluster: generating a keypair is the first step.
				// Fall back to an empty secret in that case.
				if outputFormat != "" || !(errors.Is(err, plugin.ErrNoPaasConfigs) || errors.Is(err, plugin.ErrNoSecret)) {
					return err
				}
				secret = &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}}
			}
			pks, err := crypt.NewPrivateKeysFromSecretData(secret.Data)
			if err != nil {
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
	flags.StringVarP(&privateKeyFile, argNamePrivateKeyFile, "p", "", "The file to write the private key to")
	flags.StringVarP(&publicKeyFile, argNamePublicKeyFile, "P", "", "The file to write the public key to")
	flags.StringVarP(&outputFormat, argNameOutputFormat, "o", "",
		"The output format (leave empty to use the default)")
	flags.StringVarP(&encryptionSecretName, argNameEncSecretName, "S", "",
		"The name of the secret conating the encryption keys (leave empty to use from PaasConfig)")

	for envVar, arg := range map[string]string{
		"PAAS_PRIVATE_KEY_PATH":  argNamePrivateKeyFile,
		"PAAS_PUBLIC_KEY_PATH":   argNamePublicKeyFile,
		"PAAS_FORMAT":            argNameOutputFormat,
		"PAAS_ENCRYPTION_SECRET": argNameEncSecretName,
	} {
		if err := viper.BindPFlag(arg, flags.Lookup(arg)); err != nil {
			logrus.Errorf("key binding for %s failed: %v", arg, err)
		}
		if err := viper.BindEnv(arg, envVar); err != nil {
			logrus.Errorf("paas binding failed for %s: %v", arg, err)
		}
	}
	return cmd
}
