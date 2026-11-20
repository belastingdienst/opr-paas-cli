/*
Copyright 2026, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package paasfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	preserveOldValue = "AAAAoldciphertextAAAAoldciphertextAAAAoldciphertextAAAA"
	preserveNewValue = "BBBBnewciphertext"
	preserveHalf     = len(preserveOldValue) / 2
	testFileMode     = 0o600
)

// preservePaasYAML returns a v1alpha2 Paas file with one secret, written in the given YAML style.
func preservePaasYAML(secretLine string) string {
	return `---
# a comment that preserve mode keeps
apiVersion: cpet.belastingdienst.nl/v1alpha2
kind: Paas
metadata:
  name: tst-tst
spec:
  secrets:
` + secretLine + `
`
}

// setPaas writes content to a temp file and replaces its secret through SetPaas in the given output format.
func setPaas(t *testing.T, content string, format Format) (*File, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "paas.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), testFileMode))

	f := &File{Path: path, OutputFormat: format}
	oldPaas, err := f.GetPaas()
	require.NoError(t, err)
	newPaas := oldPaas.DeepCopy()
	for key := range newPaas.Spec.Secrets {
		newPaas.Spec.Secrets[key] = preserveNewValue
	}
	return f, f.SetPaas(*newPaas)
}

// setPaasPreserve runs setPaas in preserve mode and returns the resulting file content.
func setPaasPreserve(t *testing.T, content string, format Format) (string, error) {
	t.Helper()
	f, err := setPaas(t, content, format)
	result, contentErr := f.getContent()
	require.NoError(t, contentErr)
	return string(result), err
}

func TestSetPaasPreserveOneLine(t *testing.T) {
	result, err := setPaasPreserve(t, preservePaasYAML("    ssh://git@example.com/repo: "+preserveOldValue),
		PreserveFormat)
	require.NoError(t, err)
	assert.Contains(t, result, preserveNewValue)
	assert.NotContains(t, result, preserveOldValue)
	assert.Contains(t, result, "# a comment that preserve mode keeps")
}

func TestSetPaasPreserveSingleLineBlock(t *testing.T) {
	result, err := setPaasPreserve(t, preservePaasYAML("    ssh://git@example.com/repo: |\n      "+preserveOldValue),
		PreserveFormat)
	require.NoError(t, err)
	assert.Contains(t, result, preserveNewValue)
	assert.NotContains(t, result, preserveOldValue)
}

func TestSetPaasPreserveWrappedValueFails(t *testing.T) {
	for name, secretLine := range map[string]string{
		"plain scalar wrapped over lines": "    ssh://git@example.com/repo: " + preserveOldValue[:preserveHalf] +
			"\n      " + preserveOldValue[preserveHalf:],
		"literal block over lines": "    ssh://git@example.com/repo: |\n      " + preserveOldValue[:preserveHalf] +
			"\n      " + preserveOldValue[preserveHalf:],
	} {
		t.Run(name, func(t *testing.T) {
			content := preservePaasYAML(secretLine)
			result, err := setPaasPreserve(t, content, PreserveFormat)
			require.Error(t, err, "a value that cannot be replaced must not be skipped silently")
			assert.Contains(t, err.Error(), "tst-tst")
			assert.Contains(t, err.Error(), "--outputFormat auto")
			assert.Equal(t, content, result, "file content is left unchanged")
		})
	}
}

func TestSetPaasAutoWrappedValue(t *testing.T) {
	content := preservePaasYAML("    ssh://git@example.com/repo: " + preserveOldValue[:preserveHalf] +
		"\n      " + preserveOldValue[preserveHalf:])
	f, err := setPaas(t, content, AutoFormat)
	require.NoError(t, err, "auto format rewrites the file from the Paas, so nothing is skipped")
	paas, err := f.GetPaas()
	require.NoError(t, err)
	for _, value := range paas.Spec.Secrets {
		assert.Equal(t, preserveNewValue, strings.TrimSpace(value))
	}
}
