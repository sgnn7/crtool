package ssl

import (
	"errors"

	"github.com/sgnn7/crtool/pkg/certificates"
)

func GetServerCertificate(host string, port string, certType certificates.CertType) error {
	return errors.New("IMPLEMENT ME")
}
