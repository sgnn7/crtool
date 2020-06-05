package validation

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"time"
)

type ValidationType int

const (
	ValidationTypeSubject ValidationType = 0

	// https://tools.ietf.org/html/rfc5280#section-4.1.2.5
	ValidationTypeNotBefore ValidationType = 1
	ValidationTypeNotAfter  ValidationType = 2

	// https://tools.ietf.org/html/rfc5280#section-4.1.2.4
	ValidationTypeIssuer ValidationType = 3

	// This isn't a validation per-se - it's more for visual indication
	ValidationTypeCACert ValidationType = 4

	// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
	ValidationTypeBasicContstraint ValidationType = 5

	// https://tools.ietf.org/html/rfc5280#section-5.1.2.6
	ValidationTypeRevocationList ValidationType = 6
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
		failure.Message = fmt.Sprintf("issuer: issuer of '%s' is not correct (expected: '%s', actual: '%s')",
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

func ValidateBasicConstraint(cert x509.Certificate) (ValidationResult, error) {
	if !cert.BasicConstraintsValid {
		failure := ValidationResultFail
		failure.Message = "basicConstraint: cert fails basic constraints" +
			"(one of `IsCA`, `MaxPathLen`, or `MaxPathLenZero`)"
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

func downloadFile(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)

	return buf.Bytes(), nil
}

func ValidateCRLRevocation(cert x509.Certificate, crlEndpoints []string) (ValidationResult, error) {
	for _, crlEndpoint := range crlEndpoints {
		crlListBuf, err := downloadFile(crlEndpoint)
		if err != nil {
			failure := ValidationResultFail
			failure.Message = err.Error()
			return failure, nil
		}

		crlList, err := x509.ParseCRL(crlListBuf)
		if err != nil {
			failure := ValidationResultFail
			failure.Message = err.Error()
			return failure, nil
		}

		for _, revokedCert := range crlList.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
				failure := ValidationResultFail
				failure.Message = fmt.Sprintf("CRL: cert '%s' was revoked via CRL", cert.Subject)
				return failure, nil
			}
		}
	}

	return ValidationResultPass, nil
}
