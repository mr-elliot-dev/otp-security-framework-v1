package endpoint

import (
	"context"
	"strings"

	"github.com/yourorg/otpsec/internal/httpclient"
)

type Finding struct {
	Path   string
	Status int
	Notes  string
}

var commonPaths = []string{
	"/otp", "/otp/request", "/otp/verify", "/auth/otp",
	"/api/otp", "/api/v1/otp", "/verify-otp", "/send-otp",
	"/2fa", "/mfa/verify",
}

// Discover issues HEAD/GET probes to known OTP-related paths.
// Authorized scope only — caller must have configured the allowlist.
func Discover(ctx context.Context, c *httpclient.Client, base string) []Finding {
	var out []Finding
	base = strings.TrimRight(base, "/")
	for _, p := range commonPaths {
		resp, err := c.Do(ctx, "GET", base+p, nil)
		if err != nil {
			out = append(out, Finding{Path: p, Status: 0, Notes: "unreachable"})
			continue
		}
		notes := "not present"
		if resp.StatusCode != 404 {
			notes = "potential OTP endpoint"
		}
		out = append(out, Finding{Path: p, Status: resp.StatusCode, Notes: notes})
	}
	return out
}