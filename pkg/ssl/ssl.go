package ssl

import (
	"crypto/tls"
	"errors"
	"log"
	"net"

	"github.com/sgnn7/crtool/pkg/cli"
	"github.com/sgnn7/crtool/pkg/encoding"
)

var InsecureTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func GetServerCertificate(host string, port string, encType encoding.EncodingType, options cli.Options) error {
	if host == "" {
		return errors.New("host not specified!")
	}

	if port == "" {
		return errors.New("port not specified!")
	}

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

	rawCerts := make([][]byte, len(conn.ConnectionState().PeerCertificates))
	for idx, cert := range conn.ConnectionState().PeerCertificates {
		rawCerts[idx] = cert.Raw
	}

	encData, err := encoding.EncodeCerts(rawCerts, encType)
	if err != nil {
		return err
	}

	if options.Debug {
		log.Printf("Certificates retrieved")
	}

	return options.HandleOutput(string(encData))
}
