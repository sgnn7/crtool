package providers

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/url"
	"strings"
)

var InsecureTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func composeEndpoint(host string, port string) (string, string, error) {
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

// TODO Use a specialized logger
func GetTLSCertificates(target string, port string, debug bool) ([]*x509.Certificate, string, error) {
	hostname, endpoint, err := composeEndpoint(target, port)
	if err != nil {
		return nil, "", err
	}

	if debug {
		log.Printf("Dialing '%s'...", endpoint)
	}

	conn, err := tls.Dial("tcp", endpoint, InsecureTLSConfig)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()

	if debug {
		log.Printf("Connection established")
	}

	return conn.ConnectionState().PeerCertificates, hostname, nil
}
