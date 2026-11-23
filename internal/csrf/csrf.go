package csrf

import (
	"net/http"
	"strings"

	"github.com/yourorg/otpsec/internal/httpclient"
)

type Result struct {
	TokenPresent bool
	SameSite     string
	Notes        string
}

func Analyze(resp *httpclient.Response) Result {
	r := Result{}
	for _, c := range resp.Headers.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "samesite=strict") || strings.Contains(lc, "samesite=lax") {
			r.SameSite = "present"
		} else if strings.Contains(lc, "samesite=none") {
			r.SameSite = "none"
		}
	}
	body := strings.ToLower(string(resp.Body))
	if strings.Contains(body, "csrf") || strings.Contains(body, "xsrf") {
		r.TokenPresent = true
	}
	if !r.TokenPresent {
		r.Notes = "no CSRF token string observed in body"
	}
	if r.SameSite == "" {
		r.Notes += "; no SameSite cookie attribute"
	}
	return r
}

func CookieSecurity(resp *httpclient.Response) map[string]bool {
	out := map[string]bool{"Secure": false, "HttpOnly": false}
	for _, c := range resp.Headers.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "secure") {
			out["Secure"] = true
		}
		if strings.Contains(lc, "httponly") {
			out["HttpOnly"] = true
		}
	}
	return out
}

var _ = http.Header{}