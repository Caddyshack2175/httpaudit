package http

import (
	"crypto/tls"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientConfiguration(t *testing.T) {
	client, err := NewClient(ClientConfig{Timeout: 7, InsecureSkipVerify: true, FollowRedirects: true})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.Timeout != 7*time.Second {
		t.Errorf("Timeout = %v, want 7s", client.Timeout)
	}
	if client.CheckRedirect != nil {
		t.Error("CheckRedirect is set when redirects should be followed")
	}

	transport, ok := client.Transport.(*stdhttp.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Errorf("TLS minimum = %x, want TLS 1.0", transport.TLSClientConfig.MinVersion)
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want configured true")
	}
	if transport.TLSNextProto == nil {
		t.Error("TLSNextProto = nil; HTTP/2 should be disabled")
	}
}

func TestNewClientProxyConfiguration(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ProxyURL:        "http://proxy.example:8080",
		Timeout:         1,
		FollowRedirects: false,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	transport := client.Transport.(*stdhttp.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS11 || transport.TLSClientConfig.MaxVersion != tls.VersionTLS11 {
		t.Errorf("proxy TLS versions = %x-%x, want TLS 1.1 only", transport.TLSClientConfig.MinVersion, transport.TLSClientConfig.MaxVersion)
	}
	req, _ := stdhttp.NewRequest("GET", "https://target.example", nil)
	proxyURL, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("proxy function error = %v", err)
	}
	if proxyURL.String() != "http://proxy.example:8080" {
		t.Errorf("proxy URL = %q", proxyURL)
	}
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect = nil when redirects should not be followed")
	}
	if err := client.CheckRedirect(req, nil); err != stdhttp.ErrUseLastResponse {
		t.Errorf("CheckRedirect() error = %v, want http.ErrUseLastResponse", err)
	}
}

func TestNewClientRejectsInvalidProxyURL(t *testing.T) {
	_, err := NewClient(ClientConfig{ProxyURL: "http://[::1", Timeout: 1})
	if err == nil || !strings.Contains(err.Error(), "invalid proxy URL") {
		t.Fatalf("NewClient() error = %v, want invalid proxy URL", err)
	}
}

func TestNewClientRedirectBehavior(t *testing.T) {
	var destination string
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/redirect" {
			stdhttp.Redirect(w, r, "/destination", stdhttp.StatusFound)
			return
		}
		destination = r.URL.Path
		w.WriteHeader(stdhttp.StatusNoContent)
	}))
	defer server.Close()

	noFollow, err := NewClient(ClientConfig{Timeout: 2, FollowRedirects: false})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noFollow.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatalf("no-follow request error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != stdhttp.StatusFound {
		t.Errorf("no-follow status = %d, want 302", resp.StatusCode)
	}

	follow, err := NewClient(ClientConfig{Timeout: 2, FollowRedirects: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = follow.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatalf("follow request error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != stdhttp.StatusNoContent || destination != "/destination" {
		t.Errorf("follow response = status %d, destination %q", resp.StatusCode, destination)
	}
}
