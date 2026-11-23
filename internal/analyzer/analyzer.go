package analyzer

import (
	"net/http"
	"strings"
)

type Result struct {
	Title    string
	Severity string // Info, Low, Medium, High
	Detail   string
}

func ClassifyOTPResponse(status int, body []byte) (bool, string) {
	text := strings.ToLower(string(body))
	switch {
	case status >= 500:
		return false, "server error (possible DoS surface)"
	case status == 429:
		return false, "rate limited"
	case status == 401 || status == 403:
		return false, "rejected"
	}
	successWords := []string{"verified", "success", "welcome", "authenticated"}
	for _, w := range successWords {
		if strings.Contains(text, w) {
			return true, "success keyword detected"
		}
	}
	return false, "no success keyword"
}

func AnalyzeHeaders(h http.Header) []Result {
	var out []Result
	required := map[string]string{
		"Strict-Transport-Security": "HSTS missing — downgrade risk",
		"X-Content-Type-Options":    "MIME sniffing possible",
		"X-Frame-Options":           "clickjacking risk",
		"Content-Security-Policy":   "CSP not set",
	}
	for k, msg := range required {
		if h.Get(k) == "" {
			out = append(out, Result{Title: k + " missing", Severity: "Medium", Detail: msg})
		}
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "apache/2.2") {
		out = append(out, Result{Title: "Outdated server", Severity: "Medium", Detail: "Apache 2.2 detected"})
	}
	return out
}