package providers

import (
	"crypto/x509"
	"log"
	"strings"
)

// TODO: Use logger instead of debug flag
func GetCertificates(target string, port string, debug bool) ([]*x509.Certificate, string, error) {
	if strings.HasPrefix(target, "file://") {
		if debug {
			log.Printf("Using file cert provider to resolve '%s'", target)
		}

		return GetFileCertificates(target, debug)
	}

	return GetTLSCertificates(target, port, debug)
}
