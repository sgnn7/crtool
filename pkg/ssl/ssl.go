package ssl

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"log"
	"net"

	"github.com/sgnn7/crtool/pkg/certificates"
)

var InsecureTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func GetServerCertificate(host string, port string, certType certificates.CertType) error {
	target := net.JoinHostPort(host, port)
	log.Printf("Dialing '%s'...", target)

	conn, err := tls.Dial("tcp", target, InsecureTLSConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("Connection established")

	var buf bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err := pem.Encode(&buf, &pem.Block{
			Bytes: cert.Raw,
			Type:  "CERTIFICATE",
		})
		if err != nil {
			return err
		}
	}
	log.Printf(buf.String())

	return nil
}
