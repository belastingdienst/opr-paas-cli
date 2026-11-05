/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasobject"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasresource"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/reencrypt"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func reencryptCmd() *cobra.Command {
	var (
		privateKeyFileGlob   string
		encryptionSecretName string
		publicKeyFile        string
		outputFormat         string
		labelFilters         string
		annotationFilters    string
	)

	cmd := &cobra.Command{
		Use:   "reencrypt [command options]",
		Short: "reencrypt using old private key to decrypt and new public key to encrypt",
		//revive:disable-next-line
		Long: `parse yaml/json files with paas objects, decrypt the Secrets with the previous private key,
reencrypt with the new public key and write the Paas back to the file in either yaml or json format.`,
		//revive:disable-next-line
		RunE: func(command *cobra.Command, args []string) error {
			var conversionService reencrypt.ConversionService
			var objects paasobject.Objects
			var err error

			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}

			if len(args) > 0 {
				logrus.Debugf("Reading from path: %v", args)
				if objects, err = paasfile.FilesFromPaths(args, outputFormat); err != nil {
					return err
				}
			} else {
				logrus.Debugf("Reading from k8s")
				if objects, err = paasresource.ResourcesFromK8s(command.Context()); err != nil {
					return err
				}
			}
			if debug {
				for _, o := range objects {
					p, err := o.GetPaas()
					if err != nil {
						logrus.Errorf("error while getting Paas: %v", err)
					}
					logrus.Debugf("Paas: %s", p.Name)
				}
			}

			if len(privateKeyFileGlob) > 0 {
				var privateKeyFiles []string
				privateKeyFiles, err = utils.PathToFileList([]string{privateKeyFileGlob})
				if err != nil {
					return err
				}
				conversionService = reencrypt.ConversionService{
					Factory: &reencrypt.FileCryptFactory{
						PrivateKeyFiles: privateKeyFiles,
						PublicKeyFile:   publicKeyFile,
					},
				}
			} else {
				keys, err := keysFromK8s(command.Context(), encryptionSecretName)
				if err != nil {
					return err
				}
				conversionService = reencrypt.ConversionService{
					Factory: &reencrypt.KeyCryptFactory{
						Keys: keys,
					},
				}
			}

			err = conversionService.ReencryptObjects(objects, labelFilters, annotationFilters)
			if err != nil {
				return err
			}
			return objects.Write(command.Context())
		},
		//revive:disable-next-line
		Example: `kubectl-paas reencrypt --privateKeyFiles "/tmp/priv" --publicKeyFile "/tmp/pub" [file or dir] ([file or dir]...)`,
	}

	flags := cmd.Flags()
	flags.StringVarP(&privateKeyFileGlob, argNamePrivateKeyFiles, "p", "", "The file to read the private key from")
	flags.StringVarP(&publicKeyFile, argNamePublicKeyFile, "P", "", "The file to read the public key from")
	flags.StringVarP(&encryptionSecretName, argNameEncSecretName, "S", "",
		"The name of the secret conatining the encryption keys (leave empty to use from PaasConfig)")
	flags.StringVar(
		&outputFormat,
		argNameOutputFormat,
		"auto",
		"The outputformat for writing a Paas, either yaml (machine formatted), json (machine formatted), "+
			"auto (which will use input format as output, machine formatted) or preserve (which will use the input "+
			"format and preserve the original syntax including for example comments) ",
	)
	flags.StringVarP(&labelFilters, argNameLabelSelector, "l", "", "Filter by labels (supports =, == and !=)")
	flags.StringVarP(&annotationFilters, argNameAnnotationSelector, "a", "",
		"Filter by annotations (supports =, == and !=)")

	for envVar, arg := range map[string]string{
		"PAAS_PRIVATE_KEY_PATH":    argNamePrivateKeyFiles,
		"PAAS_PUBLIC_KEY_PATH":     argNamePublicKeyFile,
		"PAAS_OUTPUT_FORMAT":       argNameOutputFormat,
		"PAAS_ENCRYPTION_SECRET":   argNameEncSecretName,
		"PAAS_LABEL_SELECTOR":      argNameLabelSelector,
		"PAAS_ANNOTATION_SELECTOR": argNameAnnotationSelector,
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
