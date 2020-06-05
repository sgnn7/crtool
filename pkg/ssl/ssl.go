package ssl

import (
	"crypto/x509"
	"errors"
	"log"
	"time"

	certProviders "github.com/sgnn7/crtool/pkg/certificates/providers"
	"github.com/sgnn7/crtool/pkg/certificates/validation"
	"github.com/sgnn7/crtool/pkg/cli"
	"github.com/sgnn7/crtool/pkg/encoding"
)

func GetServerCert(target string, port string, encType encoding.EncodingType, options cli.Options) error {
	certs, _, err := certProviders.GetTLSCertificates(target, port, options.Debug)
	if err != nil {
		return err
	}

	rawCerts := make([][]byte, len(certs))
	for idx, cert := range certs {
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

func VerifyServerCertChain(target string, port string, options cli.Options) error {
	certs, host, err := certProviders.GetTLSCertificates(target, port, options.Debug)
	if err != nil {
		return err
	}

	validations := []validation.ValidationResult{}
	numOfCerts := len(certs)

	// Global chain verifications
	leafCert := certs[0]
	hostnameValidation, _ := validation.ValidateHostname(host, leafCert)
	validations = append(validations, hostnameValidation)
	log.Printf("%s %-23s %s", hostnameValidation, "Hostname:", host)

	certChainValidation, _ := validation.ValidateChain(certs)
	validations = append(validations, certChainValidation)
	log.Printf("%s %-23s %s", certChainValidation, "Chain Validity:", "System CA store")
	log.Println()

	// Inidividual cert validations
	for idx, cert := range certs {
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
			issuerCert = certs[idx+1]
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
