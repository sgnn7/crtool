package ssl

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"time"

	"github.com/sgnn7/crtool/pkg/certificates/validation"
	"github.com/sgnn7/crtool/pkg/cli"
	"github.com/sgnn7/crtool/pkg/encoding"
)

var InsecureTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func composeTargetStr(host string, port string) (string, error) {
	if host == "" {
		return "", errors.New("host not specified!")
	}

	if port == "" {
		return "", errors.New("port not specified!")
	}

	return net.JoinHostPort(host, port), nil
}

func GetServerCert(host string, port string, encType encoding.EncodingType, options cli.Options) error {
	target, err := composeTargetStr(host, port)
	if err != nil {
		return err
	}

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

func VerifyServerCertChain(host string, port string, options cli.Options) error {
	target, err := composeTargetStr(host, port)
	if err != nil {
		return err
	}

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

	numOfCerts := len(conn.ConnectionState().PeerCertificates)

	// Global chain verifications
	leafCert := conn.ConnectionState().PeerCertificates[0]
	hostnameValidation, _ := validation.ValidateHostname(host, leafCert)
	log.Printf("%s %-23s %s", hostnameValidation, "Hostname:", host)

	certChainValidation, _ := validation.ValidateChain(conn.ConnectionState().PeerCertificates)
	log.Printf("%s %-23s %s", certChainValidation, "Chain Validity:", "System CA store")
	log.Println()

	// Inidividual cert validations
	for idx, cert := range conn.ConnectionState().PeerCertificates {
		log.Printf("Certificate: %d/%d", idx+1, numOfCerts)
		log.Println()

		subjValidation, _ := validation.ValidateSubject(cert.Subject)
		log.Printf("%s %-23s '%s'", subjValidation, "Subject:", cert.Subject)

		notBeforeValidation, _ := validation.ValidateNotBefore(cert.NotBefore)
		log.Printf("%s %-23s %s", notBeforeValidation, "Validity (NotBefore):",
			cert.NotBefore.Format(time.RFC3339))

		notAfterValidation, _ := validation.ValidateNotAfter(cert.NotAfter)
		log.Printf("%s %-23s %s", notAfterValidation, "Validity (NotAfter):",
			cert.NotAfter.Format(time.RFC3339))

		issuerValidation, _ := validation.ValidateIssuer(cert.Issuer)
		log.Printf("%s %-23s '%s'", issuerValidation, "Issuer:", cert.Issuer)

		caValidation, _ := validation.ValidateCA(cert.IsCA)
		log.Printf("%s %-23s %v", caValidation, "CA Cert:", cert.IsCA)

		if idx < numOfCerts-1 {
			log.Println()
		}
	}

	if options.Debug {
		log.Printf("Certificates retrieved")
	}

	return nil
}
