package providers

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

const fileSchemaStr = "file://"

func loadCertificates(path string, debug bool) ([]*x509.Certificate, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if debug {
		log.Printf("Loaded %d bytes from %s", len(bytes), path)

		log.Printf("Decoding PEM...")
	}

	certs := []*x509.Certificate{}

	for {
		block, rest := pem.Decode(bytes)
		if block == nil {
			return nil, errors.New("failed to decode PEM block containing public key")
		}

		if debug {
			log.Printf("Block was decoded (%s)", block.Type)
		}

		if block.Type != "CERTIFICATE" {
			return nil, errors.New("a key did not have the expected 'CERTIFICATE' header")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		if debug {
			log.Printf("Certificate parsed for '%s'", cert.Subject)
		}

		certs = append(certs, cert)

		bytes = rest

		if len(bytes) == 0 {
			if debug {
				log.Printf("Finished reading the PEM file")
			}

			break
		}
	}

	return certs, nil
}

// TODO Use a specialized logger
func GetFileCertificates(target string, debug bool) ([]*x509.Certificate, string, error) {
	if debug {
		log.Printf("Resolving '%s'...", target)
	}

	path := strings.TrimLeft(target, fileSchemaStr)

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}

	if debug {
		log.Printf("Absolute path is %s", absPath)
	}

	certs, err := loadCertificates(absPath, debug)
	if err != nil {
		return nil, "", err
	}

	hostname := ""
	if len(certs) > 0 {
		hostname = certs[0].Subject.CommonName
	}

	return certs, hostname, nil
}
