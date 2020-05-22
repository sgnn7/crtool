package ssl

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"log"
	"net"

	"github.com/sgnn7/crtool/pkg/certificates"
	"github.com/sgnn7/crtool/pkg/cli"
)

var InsecureTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func GetServerCertificate(host string, port string, certType certificates.CertType, options cli.Options) error {
	target := net.JoinHostPort(host, port)

	if options.Debug {
		log.Printf("Dialing '%s'...", target)
	}

	conn, err := tls.Dial("tcp", target, InsecureTLSConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	if options.Debug {
		log.Printf("Connection established")
	}

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

	if options.Debug {
		log.Printf("Certificates retrieved:")
	}

	fmt.Printf(buf.String())

	return nil
}
