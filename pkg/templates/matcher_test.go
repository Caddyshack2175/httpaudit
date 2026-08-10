package templates

import (
	"net/http"
	"strings"
	"testing"
)

func TestMatchCriteriaMatch(t *testing.T) {
	criteria := MatchCriteria{
		Headers: map[string]string{"Server": `(?i)^example/\d+$`},
		Body:    []string{`token=([a-z]+)`, `not-present`},
	}
	headers := http.Header{"Server": []string{"Example/12"}}

	got, err := criteria.Match(headers, "prefix token=secret suffix")
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if !got.Matched || got.MatchedBy != "header:Server" || got.MatchedValue != "Example/12" {
		t.Fatalf("Match() = %#v", got)
	}
	if len(got.AllMatches) != 2 || got.AllMatches[1] != "body:token=([a-z]+)" {
		t.Errorf("AllMatches = %#v", got.AllMatches)
	}
}

func TestMatchCriteriaBodyMatchTruncatesValue(t *testing.T) {
	value := strings.Repeat("a", 120)
	got, err := (&MatchCriteria{Body: []string{`a+`}}).Match(nil, value)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MatchedValue) != 103 || !strings.HasSuffix(got.MatchedValue, "...") {
		t.Errorf("MatchedValue = %q (length %d)", got.MatchedValue, len(got.MatchedValue))
	}
}

func TestMatchCriteriaNoMatchAndRegexErrors(t *testing.T) {
	got, err := (&MatchCriteria{Headers: map[string]string{"X-Test": "expected"}}).Match(http.Header{}, "")
	if err != nil || got.Matched || got.MatchedBy != "" || len(got.AllMatches) != 0 {
		t.Fatalf("no-match result = %#v, error = %v", got, err)
	}

	if _, err := (&MatchCriteria{Headers: map[string]string{"X-Test": "["}}).Match(http.Header{}, ""); err == nil || !strings.Contains(err.Error(), "header X-Test") {
		t.Fatalf("invalid header regex error = %v", err)
	}
	if _, err := (&MatchCriteria{Body: []string{"["}}).Match(nil, ""); err == nil || !strings.Contains(err.Error(), "invalid regex pattern for body") {
		t.Fatalf("invalid body regex error = %v", err)
	}
}

func TestMatchesDetection(t *testing.T) {
	template := &DetectionTemplate{
		Match:         MatchCriteria{Body: []string{"admin"}},
		NegativeMatch: &MatchCriteria{Body: []string{"access denied"}},
	}

	matched, result, err := MatchesDetection(template, nil, "admin console")
	if err != nil || !matched || result == nil || !result.Matched {
		t.Fatalf("positive MatchesDetection() = %v, %#v, %v", matched, result, err)
	}

	matched, result, err = MatchesDetection(template, nil, "admin access denied")
	if err != nil || matched || result == nil || !result.Matched {
		t.Fatalf("negative MatchesDetection() = %v, %#v, %v", matched, result, err)
	}

	matched, result, err = MatchesDetection(template, nil, "ordinary page")
	if err != nil || matched || result == nil || result.Matched {
		t.Fatalf("non-match MatchesDetection() = %v, %#v, %v", matched, result, err)
	}
}

func TestBuildTechnicalDetails(t *testing.T) {
	headers := http.Header{
		"X-Test": []string{"one", "two"},
	}
	details := BuildTechnicalDetails(
		"https://example.test/path",
		headers,
		"unused body",
		&MatchResult{Matched: true},
		"Example Detection",
	)
	for _, want := range []string{
		"$ curl -skI https://example.test/path",
		"x-test: one<br>",
		"x-test: two<br>",
		"Example Detection",
	} {
		if !strings.Contains(details, want) {
			t.Errorf("BuildTechnicalDetails() missing %q in %q", want, details)
		}
	}
}

func TestTruncateString(t *testing.T) {
	if got := truncateString("short", 10); got != "short" {
		t.Errorf("truncateString(short) = %q", got)
	}
	if got := truncateString("longer", 4); got != "long..." {
		t.Errorf("truncateString(longer) = %q", got)
	}
}
