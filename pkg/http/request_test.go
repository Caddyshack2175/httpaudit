package http

import (
	"errors"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeRequestFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "request.txt")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseRequestFromFile(t *testing.T) {
	path := writeRequestFile(t, "POST /api/items?user={USER} HTTP/1.1\r\nHost: example.test:8443\r\nContent-Type: application/json\r\nX-Note: value:with:colons\r\n\r\n{\"name\":\"{USER}\"}\r\nsecond line")

	got, err := ParseRequestFromFile(path)
	if err != nil {
		t.Fatalf("ParseRequestFromFile() error = %v", err)
	}
	if got.Method != "POST" {
		t.Errorf("Method = %q, want POST", got.Method)
	}
	if got.URL != "https://example.test:8443/api/items?user={USER}" {
		t.Errorf("URL = %q", got.URL)
	}
	if got.Body != "{\"name\":\"{USER}\"}\nsecond line" {
		t.Errorf("Body = %q", got.Body)
	}
	wantHeaders := map[string]string{
		"Host":         "example.test:8443",
		"Content-Type": "application/json",
		"X-Note":       "value:with:colons",
	}
	if !reflect.DeepEqual(got.Headers, wantHeaders) {
		t.Errorf("Headers = %#v, want %#v", got.Headers, wantHeaders)
	}
}

func TestParseRequestFromFileErrors(t *testing.T) {
	tests := []struct {
		name      string
		contents  string
		wantError string
	}{
		{name: "empty", contents: "", wantError: "empty request file"},
		{name: "invalid request line", contents: "GET /only-two-parts\nHost: example.test\n", wantError: "invalid request line"},
		{name: "missing host", contents: "GET / HTTP/1.1\nAccept: */*\n", wantError: "no Host header"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRequestFromFile(writeRequestFile(t, tt.contents))
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("ParseRequestFromFile() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}

	if _, err := ParseRequestFromFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("ParseRequestFromFile() error = nil for a missing file")
	}
}

func TestMakeRequestAppliesReplacements(t *testing.T) {
	type receivedRequest struct {
		method        string
		path          string
		body          string
		header        string
		hostHeader    string
		contentLength int64
	}
	received := make(chan receivedRequest, 1)
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- receivedRequest{
			method:        r.Method,
			path:          r.URL.RequestURI(),
			body:          string(body),
			header:        r.Header.Get("X-User"),
			hostHeader:    r.Host,
			contentLength: r.ContentLength,
		}
		w.Header().Set("X-Test-Response", "yes")
		w.WriteHeader(stdhttp.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer server.Close()

	template := &RequestTemplate{
		Method: "POST",
		URL:    server.URL + "/users/{USER}?doc={DOC}",
		Headers: map[string]string{
			"Host":           "ignored.example",
			"Content-Length": "9999",
			"X-User":         "{USER}:{DOC}",
		},
		Body: "owner={USER}&doc={DOC}",
	}
	replacements := map[string]string{"USER": "alice", "DOC": "42"}

	got := MakeRequest(template, server.Client(), replacements)
	if got.NetworkError != nil {
		t.Fatalf("MakeRequest() NetworkError = %v", got.NetworkError)
	}
	if got.StatusCode != stdhttp.StatusCreated || got.ResponseBody != "created" || got.ResponseSize != len("created") {
		t.Errorf("unexpected response result: %#v", got)
	}
	if stdhttp.Header(got.ResponseHeaders).Get("X-Test-Response") != "yes" {
		t.Errorf("response header = %q, want yes", stdhttp.Header(got.ResponseHeaders).Get("X-Test-Response"))
	}
	if got.URL != server.URL+"/users/alice?doc=42" {
		t.Errorf("result URL = %q", got.URL)
	}
	if !reflect.DeepEqual(got.Replacements, replacements) {
		t.Errorf("result replacements = %#v, want %#v", got.Replacements, replacements)
	}

	wantReceived := receivedRequest{
		method:        "POST",
		path:          "/users/alice?doc=42",
		body:          "owner=alice&doc=42",
		header:        "alice:42",
		hostHeader:    strings.TrimPrefix(server.URL, "http://"),
		contentLength: int64(len("owner=alice&doc=42")),
	}
	if request := <-received; !reflect.DeepEqual(request, wantReceived) {
		t.Errorf("received request = %#v, want %#v", request, wantReceived)
	}
	if template.Headers["X-User"] != "{USER}:{DOC}" {
		t.Error("MakeRequest() mutated the request template headers")
	}
}

func TestMakeRequestReportsConstructionAndTransportErrors(t *testing.T) {
	invalid := MakeRequest(&RequestTemplate{Method: "GET", URL: "://bad URL"}, stdhttp.DefaultClient, nil)
	if invalid.NetworkError == nil {
		t.Fatal("MakeRequest() NetworkError = nil for an invalid URL")
	}

	client := &stdhttp.Client{Transport: roundTripperFunc(func(*stdhttp.Request) (*stdhttp.Response, error) {
		return nil, errors.New("transport failed")
	})}
	failed := MakeRequest(&RequestTemplate{Method: "GET", URL: "http://example.test"}, client, nil)
	if failed.NetworkError == nil || !strings.Contains(failed.NetworkError.Error(), "transport failed") {
		t.Fatalf("MakeRequest() NetworkError = %v, want transport failure", failed.NetworkError)
	}
}

type roundTripperFunc func(*stdhttp.Request) (*stdhttp.Response, error)

func (f roundTripperFunc) RoundTrip(r *stdhttp.Request) (*stdhttp.Response, error) {
	return f(r)
}

func TestRequestResultClassification(t *testing.T) {
	networkErr := errors.New("network")
	tests := []struct {
		name       string
		result     RequestResult
		successful bool
		badRequest bool
		network    bool
		category   string
	}{
		{name: "success", result: RequestResult{StatusCode: 204}, successful: true, category: "SUCCESS"},
		{name: "redirect", result: RequestResult{StatusCode: 302}, badRequest: true, category: "REDIRECT"},
		{name: "client error", result: RequestResult{StatusCode: 404}, badRequest: true, category: "CLIENT_ERROR"},
		{name: "server error", result: RequestResult{StatusCode: 503}, badRequest: true, category: "SERVER_ERROR"},
		{name: "network error", result: RequestResult{StatusCode: 200, NetworkError: networkErr}, network: true, category: "NETWORK_ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsSuccessful(); got != tt.successful {
				t.Errorf("IsSuccessful() = %v, want %v", got, tt.successful)
			}
			if got := tt.result.IsBadRequest(); got != tt.badRequest {
				t.Errorf("IsBadRequest() = %v, want %v", got, tt.badRequest)
			}
			if got := tt.result.HasNetworkError(); got != tt.network {
				t.Errorf("HasNetworkError() = %v, want %v", got, tt.network)
			}
			if got := tt.result.GetStatusCategory(); got != tt.category {
				t.Errorf("GetStatusCategory() = %q, want %q", got, tt.category)
			}
		})
	}
}
