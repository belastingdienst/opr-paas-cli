package reencrypt

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasobject"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/utils"
	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	"github.com/sirupsen/logrus"
)

// ReencryptObjects can process a list of PaasObject types, for each retrieving a Paas from a PaasObject interface
// datatype, reencrypt it, and writing it back.
func (s *ConversionService) ReencryptObjects(
	os []paasobject.Object,
	labelFilters string,
	annotationFilters string,
) error {
	var errs []error

	for _, o := range os {
		err := s.reencryptPaasObject(o, labelFilters, annotationFilters)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		err := fmt.Errorf("finished with errors: %w", errors.Join(errs...))
		logrus.Error(err)
		return err
	}

	logrus.Info("finished")
	return nil
}

// reencryptSecret decrypts and then re-encrypts a given secret using the provided
// source and destination crypt.Crypt instances.
func (s *ConversionService) reencryptSecret(crypter crypt.Cryptor,
	secret string,
) (string, error) {
	decrypted, err := crypter.Decrypt(secret)
	if err != nil {
		return "", err
	}
	logrus.Debugf("decrypted: {checksum: %s, len: %d}", utils.HashData(decrypted), len(decrypted))

	reencrypted, err := crypter.Encrypt(decrypted)
	if err != nil {
		return "", err
	}
	logrus.Debugf("reencrypted: {checksum: %s, len: %d}", utils.HashData([]byte(reencrypted)), len(reencrypted))

	return reencrypted, nil
}

// reencryptCapSecrets handles reencryption of capability secrets
func (s *ConversionService) reencryptCapSecrets(paasName string, capName string,
	capability *v1alpha2.PaasCapability, srcCrypt crypt.Cryptor,
) []error {
	var errs []error
	for key, secret := range capability.Secrets {
		reencrypted, err := s.reencryptSecret(srcCrypt, secret)
		if err != nil {
			err := fmt.Errorf("failed to decrypt/reencrypt %s.spec.capabilities.%s.Secrets[%s]: %v",
				paasName, capName, key, err)
			errs = append(errs, err)
			logrus.Error(err)
			continue
		}

		capability.Secrets[key] = reencrypted
		logrus.Infof("successfully reencrypted %s.spec.capabilities[%s].Secrets[%s]", paasName, capName, key)
	}

	return errs
}

// ReencryptPaasFile performs the core reencryption logic on PAAS data
func (s *ConversionService) reencryptPaas(originalPaas v1alpha2.Paas) (*v1alpha2.Paas, error) {
	var errs []error
	reencryptedPaas := originalPaas.DeepCopy()
	paasName := reencryptedPaas.Name

	crypter, err := s.Factory.GetCrypt(paasName)
	if err != nil {
		return nil, err
	}

	// Reencrypt main secrets
	for key, secret := range reencryptedPaas.Spec.Secrets {
		reencrypted, err := s.reencryptSecret(crypter, secret)
		if err != nil {
			err := fmt.Errorf("failed to decrypt/reencrypt %s.spec.Secrets[%s]: %v", paasName, key, err)
			errs = append(errs, err)
			logrus.Error(err)
			continue
		}

		reencryptedPaas.Spec.Secrets[key] = reencrypted
		logrus.Debugf("successfully reencrypted %s.spec.Secrets[%s]", paasName, key)
	}

	// Reencrypt capability secrets
	for capName, cap := range reencryptedPaas.Spec.Capabilities {
		errs = append(errs, s.reencryptCapSecrets(paasName, capName, &cap, crypter)...)
	}
	return reencryptedPaas, errors.Join(errs...)
}

// isFiltered checks labels or annotations if the Paas is filtered to be reencrypted, or is filtered not to.
// true means do reencrypt, false means do not reencrypt
func isFiltered(labels map[string]string, filters string) bool {
	var labelKVSplitter = regexp.MustCompile("^([^!=]*)([!=]*)(.*)")

	if filters == "" {
		return true
	}
	for _, filter := range strings.Split(filters, ",") {
		var (
			fKey           string
			negate         bool
			alsoCheckValue bool
			fValue         string
		)
		kv := labelKVSplitter.FindStringSubmatch(filter)
		if len(kv) < 2 {
			fKey = filter
		} else {
			fKey = kv[1]
		}
		if len(kv) > 2 {
			negate = strings.Contains(kv[2], "!")
			alsoCheckValue = strings.Contains(kv[2], "=")
		}

		if len(kv) > 3 {
			fValue = kv[3]
		}

		logrus.Debugf("filter: %s (%s %t %t %s) %v", filter, fKey, negate, alsoCheckValue, fValue, kv)

		labelVal, exists := labels[fKey]
		if !exists {
			if !alsoCheckValue && negate {
				continue
			}
			return false
		}
		if !alsoCheckValue {
			if negate {
				return false
			}
			// Seems like tis checks out, next filter please
			continue
		}
		// If labelVal is the same as fValue, and negate is false, return false
		// If labelVal is the same as fValue, and negate is true, continue
		// If labelVal differs from fValue, and negate is false, continue
		// If labelVal differs from fValue, and negate is true, return false
		if (labelVal == fValue) == negate {
			return false
		}
	}
	return true
}

// reencryptPaasFile performs the core reencryption logic on PAAS data
func (s *ConversionService) reencryptPaasObject(
	object paasobject.Object,
	labelFilters string,
	annotationFilters string,
) error {
	paas, err := object.GetPaas()
	if err != nil {
		return err
	}
	logrus.Debugf("anno selector %s", annotationFilters)
	if isAnnoFlt := isFiltered(paas.Annotations, annotationFilters); !isAnnoFlt {
		logrus.Infof("Skipping %s (annotation selector)", paas.Name)
		return err
	}
	logrus.Debugf("label selector %s", labelFilters)
	if isLblFlt := isFiltered(paas.Labels, labelFilters); !isLblFlt {
		logrus.Infof("Skipping %s (label selector)", paas.Name)
		return err
	}

	logrus.Infof("Reencrypting %s", paas.Name)
	// Making a copy so we don;t overwrite object.paas. We do that with SetPaas.
	reencryptedPaas, err := s.reencryptPaas(*paas)
	if err != nil {
		return err
	}
	return object.SetPaas(*reencryptedPaas)
}
