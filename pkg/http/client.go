package http

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ClientConfig holds HTTP client configuration
type ClientConfig struct {
	ProxyURL           string
	Timeout            int
	InsecureSkipVerify bool
	FollowRedirects    bool
}

// NewClient creates a configured HTTP client
func NewClient(config ClientConfig) (*http.Client, error) {
	// Configure TLS based on proxy usage
	var tlsConfig *tls.Config

	if config.ProxyURL != "" {
		// Force TLS 1.1 with specific cipher suites to prevent HTTP/2 negotiation when using proxy
		tlsConfig = &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			},
			PreferServerCipherSuites: true,
			InsecureSkipVerify:       true,
			MinVersion:               tls.VersionTLS11,
			MaxVersion:               tls.VersionTLS11,
		}
	} else {
		// Allow TLS 1.0-1.3 for wider compatibility when not using proxy
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		}
	}

	// Configure proxy function
	var proxyFunc func(*http.Request) (*url.URL, error)
	if config.ProxyURL != "" {
		proxyParsed, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		// Use the built-in ProxyURL function
		proxyFunc = http.ProxyURL(proxyParsed)
	} else {
		// Use environment proxy if no explicit proxy configured
		proxyFunc = http.ProxyFromEnvironment
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		TLSNextProto:    make(map[string]func(authority string, c *tls.Conn) http.RoundTripper), // Disable HTTP/2
		Proxy:           proxyFunc,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}

	// Configure redirect behavior
	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client, nil
}
