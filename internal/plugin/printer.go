/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package plugin

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"sigs.k8s.io/yaml"
)

// Print output an object via an io.Writer in a machine-readable way
func Print(o interface{}, format paasfile.Format, writer io.Writer) error {
	switch format {
	case paasfile.JSONFormat:
		data, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			return err
		}

		_, err = writer.Write(data)
		if err != nil {
			return err
		}

		// json.MarshalIndent doesn't add the final newline
		_, err = io.WriteString(writer, "\n")
		if err != nil {
			return err
		}

	case paasfile.YAMLFormat:
		data, err := yaml.Marshal(o)
		if err != nil {
			return err
		}

		_, err = writer.Write(append([]byte("---\n"), data...))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("cannot use %s, only yaml/json is valid", format.String())
	}

	return nil
}
