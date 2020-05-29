package validation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

type ValidationType int

const (
	ValidationTypeSubject   ValidationType = 0
	ValidationTypeNotBefore ValidationType = 1
	ValidationTypeNotAfter  ValidationType = 2
	ValidationTypeIssuer    ValidationType = 3
	ValidationTypeCACert    ValidationType = 4
)

var ValidationResultPass = ValidationResult{
	ResultStr: " OK ",
	Success:   true,
}

var ValidationResultSkip = ValidationResult{
	ResultStr: "----",
	Success:   true,
}

var ValidationResultFail = ValidationResult{
	ResultStr: "FAIL",
	Success:   false,
}

type ValidationResult struct {
	ResultStr string
	Message   string
	Success   bool
}

func (result ValidationResult) String() string {
	return fmt.Sprintf("[%-4s]", result.ResultStr)
}

func ValidateSubject(subject pkix.Name) (ValidationResult, error) {
	return ValidationResultSkip, nil
}

func ValidateCA(isCA bool) (ValidationResult, error) {
	return ValidationResultSkip, nil
}

func ValidateIssuer(issuer pkix.Name) (ValidationResult, error) {
	return ValidationResultSkip, nil
}

func ValidateNotBefore(notBefore time.Time) (ValidationResult, error) {
	if time.Now().Before(notBefore) {
		return ValidationResultFail, nil
	}

	return ValidationResultPass, nil
}

func ValidateHostname(hostname string, hostCert *x509.Certificate) (ValidationResult, error) {
	hostnameVerificationErr := hostCert.VerifyHostname(hostname)
	if hostnameVerificationErr != nil {
		// TODO: Show error
		return ValidationResultFail, nil
	}

	return ValidationResultPass, nil
}

func ValidateChain(certs []*x509.Certificate) (ValidationResult, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		// TODO: Show error
		return ValidationResultFail, nil
	}

	intermediateCerts := certs[1:]
	intCertPool := x509.NewCertPool()
	for _, cert := range intermediateCerts {
		intCertPool.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intCertPool,
	}

	leafCert := certs[0]
	if _, err := leafCert.Verify(opts); err != nil {
		// TODO: Show error
		return ValidationResultFail, nil
	}

	return ValidationResultPass, nil
}

func ValidateNotAfter(notAfter time.Time) (ValidationResult, error) {
	if time.Now().After(notAfter) {
		return ValidationResultFail, nil
	}

	return ValidationResultPass, nil
}
