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

func ValidateIssuer(cert *x509.Certificate, issuer *x509.Certificate) (ValidationResult, error) {
	// If it's the last cert, it's self-signed or we need to continue on with the third-party chain
	// TODO: Implement the correct chain bubbling for self-signed CAs
	// TODO: Implement the correct chain bubbling for certs with separate CA chains
	if issuer == nil {
		return ValidationResultSkip, nil
	}

	// Check CN
	if cert.Issuer.String() != issuer.Subject.String() {
		failure := ValidationResultFail
		failure.Message = fmt.Sprintf("issuer: issuer of '%s' is not the next cert in chain '%s' (was '%s')",
			cert.Subject,
			cert.Issuer,
			issuer.Subject)
		return failure, nil
	}

	// Then check the signature
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		failure := ValidationResultFail
		failure.Message = fmt.Sprintf("issuer: signature on '%s' is not a valid signature from '%s' (%s)",
			cert.Subject,
			issuer.Subject,
			err.Error())
		return failure, nil
	}

	return ValidationResultPass, nil
}

func ValidateNotBefore(notBefore time.Time) (ValidationResult, error) {
	if time.Now().Before(notBefore) {
		failure := ValidationResultFail
		failure.Message = "notBefore: current datetime is before cert validity start time"
		return failure, nil
	}

	return ValidationResultPass, nil
}

func ValidateNotAfter(notAfter time.Time) (ValidationResult, error) {
	if time.Now().After(notAfter) {
		failure := ValidationResultFail
		failure.Message = "notAfter: current datetime is after cert validity end time"
		return failure, nil
	}

	return ValidationResultPass, nil
}

func ValidateHostname(hostname string, hostCert *x509.Certificate) (ValidationResult, error) {
	hostnameVerificationErr := hostCert.VerifyHostname(hostname)
	if hostnameVerificationErr != nil {
		failure := ValidationResultFail
		failure.Message = hostnameVerificationErr.Error()
		return failure, nil
	}

	return ValidationResultPass, nil
}

func ValidateChain(certs []*x509.Certificate) (ValidationResult, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		failure := ValidationResultFail
		failure.Message = err.Error()
		return failure, nil
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
		failure := ValidationResultFail
		failure.Message = err.Error()
		return failure, nil
	}

	return ValidationResultPass, nil
}
