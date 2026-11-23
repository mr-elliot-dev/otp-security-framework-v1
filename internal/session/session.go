package session

import (
	"strings"

	"github.com/yourorg/otpsec/internal/httpclient"
)

type Report struct {
	Cookies       []string
	SecureFlags   bool
	HttpOnlyFlags bool
	SameSite      string
	SessionRotate bool // heuristic: different session cookie between two responses
}

func Analyze(first, second *httpclient.Response) Report {
	r := Report{}
	cookies := first.Headers.Values("Set-Cookie")
	r.Cookies = cookies
	for _, c := range cookies {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "secure") {
			r.SecureFlags = true
		}
		if strings.Contains(lc, "httponly") {
			r.HttpOnlyFlags = true
		}
		if strings.Contains(lc, "samesite=") {
			r.SameSite = "present"
		}
	}
	if second != nil {
		a := sessionID(cookies)
		b := sessionID(second.Headers.Values("Set-Cookie"))
		if a != "" && b != "" && a != b {
			r.SessionRotate = true
		}
	}
	return r
}

func sessionID(cookies []string) string {
	for _, c := range cookies {
		lc := strings.ToLower(c)
		for _, n := range []string{"session", "sess", "sid", "jsessionid", "phpsessid"} {
			if strings.HasPrefix(lc, n+"=") {
				parts := strings.SplitN(c, "=", 2)
				if len(parts) == 2 {
					return strings.SplitN(parts[1], ";", 2)[0]
				}
			}
		}
	}
	return ""
}