package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/sgnn7/crtool/pkg/certificates/validation"
	"github.com/sgnn7/crtool/pkg/cli"
	"github.com/sgnn7/crtool/pkg/encoding"
)

var InsecureTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func composeTargetStr(host string, port string) (string, string, error) {
	if host == "" {
		return "", "", errors.New("host not specified!")
	}

	if port == "" {
		return "", "", errors.New("port not specified!")
	}

	// Try to strip off the schema/path/port if someone used a URL
	url, err := url.ParseRequestURI(host)
	if err == nil {
		hostPort := strings.Split(url.Host, ":")
		if len(hostPort) < 2 {
			hostPort = append(hostPort, "443")
		}

		return hostPort[0], hostPort[0] + ":" + hostPort[1], nil
	}

	return host, net.JoinHostPort(host, port), nil
}

func GetServerCert(host string, port string, encType encoding.EncodingType, options cli.Options) error {
	host, target, err := composeTargetStr(host, port)
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
	host, target, err := composeTargetStr(host, port)
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

	validations := []validation.ValidationResult{}

	numOfCerts := len(conn.ConnectionState().PeerCertificates)

	// Global chain verifications
	leafCert := conn.ConnectionState().PeerCertificates[0]
	hostnameValidation, _ := validation.ValidateHostname(host, leafCert)
	validations = append(validations, hostnameValidation)
	log.Printf("%s %-23s %s", hostnameValidation, "Hostname:", host)

	certChainValidation, _ := validation.ValidateChain(conn.ConnectionState().PeerCertificates)
	validations = append(validations, certChainValidation)
	log.Printf("%s %-23s %s", certChainValidation, "Chain Validity:", "System CA store")
	log.Println()

	// Inidividual cert validations
	for idx, cert := range conn.ConnectionState().PeerCertificates {
		log.Printf("Certificate: %d/%d", idx+1, numOfCerts)
		log.Println()

		subjValidation, _ := validation.ValidateSubject(cert.Subject)
		validations = append(validations, subjValidation)
		log.Printf("%s %-23s '%s'", subjValidation, "Subject:", cert.Subject)

		notBeforeValidation, _ := validation.ValidateNotBefore(cert.NotBefore)
		validations = append(validations, notBeforeValidation)
		log.Printf("%s %-23s %s", notBeforeValidation, "Validity (NotBefore):",
			cert.NotBefore.Format(time.RFC3339))

		notAfterValidation, _ := validation.ValidateNotAfter(cert.NotAfter)
		validations = append(validations, notAfterValidation)
		log.Printf("%s %-23s %s", notAfterValidation, "Validity (NotAfter):",
			cert.NotAfter.Format(time.RFC3339))

		var issuerCert *x509.Certificate
		if idx < numOfCerts-1 {
			issuerCert = conn.ConnectionState().PeerCertificates[idx+1]
		}
		issuerValidation, _ := validation.ValidateIssuer(cert, issuerCert)
		validations = append(validations, issuerValidation)
		log.Printf("%s %-23s '%s'", issuerValidation, "Issuer:", cert.Issuer)

		caValidation, _ := validation.ValidateCA(cert.IsCA)
		validations = append(validations, caValidation)
		log.Printf("%s %-23s %v", caValidation, "CA Cert:", cert.IsCA)

		if idx < numOfCerts-1 {
			log.Println()
		}
	}

	success := true
	for _, validation := range validations {
		if !validation.Success {
			if success {
				log.Println()
			}
			success = false
			log.Printf("FAIL: %s", validation.Message)
		}
	}

	if !success {
		return errors.New("fetched certificate chain failed validation")
	}

	return nil
}
