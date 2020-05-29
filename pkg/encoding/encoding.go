package encoding

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
)

type EncodingType int

const (
	Unknown EncodingType = -1
	PEM     EncodingType = 0
	DER     EncodingType = 1
)

func NewTypeFromStr(encodingStr string) (EncodingType, error) {
	switch encodingStr {
	case "pem", "PEM":
		return PEM, nil
	case "der", "DER":
		return DER, nil
	}

	return Unknown,
		errors.New(fmt.Sprintf("encoding type '%s' is not supported!", encodingStr))
}

func EncodeCerts(rawCerts [][]byte, encType EncodingType) ([]byte, error) {
	var buf bytes.Buffer
	switch encType {
	case PEM:
		for _, cert := range rawCerts {
			err := pem.Encode(&buf, &pem.Block{
				Bytes: cert,
				Type:  "CERTIFICATE",
			})
			if err != nil {
				return []byte{}, err
			}
		}

		return buf.Bytes(), nil
	case DER:
		return rawCerts[0], nil
	}

	return []byte{},
		errors.New(fmt.Sprintf("encoding type ID:%s is not supported!", encType))
}
