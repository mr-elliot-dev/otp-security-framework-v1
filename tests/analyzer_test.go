package tests

import (
	"net/http"
	"testing"

	"github.com/yourorg/otpsec/internal/analyzer"
)

func TestClassifyOTPResponse(t *testing.T) {
	cases := []struct {
		status int
		body   string
		wantOK bool
	}{
		{200, "verified", true},
		{200, "welcome back", true},
		{401, "invalid", false},
		{429, "slow down", false},
		{500, "boom", false},
		{200, "retry", false},
	}
	for _, c := range cases {
		ok, _ := analyzer.ClassifyOTPResponse(c.status, []byte(c.body))
		if ok != c.wantOK {
			t.Fatalf("status=%d body=%q want=%v got=%v", c.status, c.body, c.wantOK, ok)
		}
	}
}

func TestAnalyzeHeaders_DetectsMissing(t *testing.T) {
	h := http.Header{}
	res := analyzer.AnalyzeHeaders(h)
	if len(res) == 0 {
		t.Fatal("expected findings for empty headers")
	}
}