package providers

import (
	"crypto/x509"
)

// TODO: Use logger instead of debug flag
func GetCertificates(target string, port string, debug bool) ([]*x509.Certificate, string, error) {
	return GetTLSCertificates(target, port, debug)
}
