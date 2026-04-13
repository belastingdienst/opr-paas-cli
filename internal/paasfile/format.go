package paasfile

import "fmt"

// Format is the type of the Paas file; json, yaml, unknown
type Format uint

// File formats supported by this package
const (
	UnknownFormat Format = iota
	AutoFormat
	DefaultFormat
	JSONFormat
	PreserveFormat
	RawFormat
	YAMLFormat
)

var fileFormatString = map[Format]string{
	AutoFormat:     "auto",
	DefaultFormat:  "default",
	JSONFormat:     "json",
	YAMLFormat:     "yaml",
	PreserveFormat: "preserve",
	RawFormat:      "raw",
	UnknownFormat:  "unknown",
}

var stringFileFormat = map[string]Format{
	"auto":     AutoFormat,
	"default":  DefaultFormat,
	"":         DefaultFormat,
	"json":     JSONFormat,
	"yaml":     YAMLFormat,
	"preserve": PreserveFormat,
	"raw":      RawFormat,
	"unknown":  UnknownFormat,
}

// Returns a string representation of fileFormat, if known.
func (ff Format) String() string {
	if s, exists := fileFormatString[ff]; exists {
		return s
	}
	return UnknownFormat.String()
}

// FormatFromString can be used to get the corresponding format for a string value
func FormatFromString(sFormat string) (Format, error) {
	if format, exists := stringFileFormat[sFormat]; exists {
		return format, nil
	}
	return UnknownFormat, fmt.Errorf("unknown file format %s", sFormat)
}
