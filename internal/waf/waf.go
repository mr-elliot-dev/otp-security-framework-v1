package waf

import (
	"context"
	"strings"

	"github.com/yourorg/otpsec/internal/httpclient"
)

// Fingerprint passively detects WAF/CDN from headers and known signatures.
// No evasion is attempted.
func Fingerprint(ctx context.Context, c *httpclient.Client, url string) map[string]string {
	found := map[string]string{}
	resp, err := c.Do(ctx, "GET", url, nil)
	if err != nil {
		found["error"] = err.Error()
		return found
	}
	sigs := map[string]string{
		"cloudflare":  "cf-ray",
		"akamai":      "akamai",
		"aws-waf":     "x-amzn",
		"incapsula":   "x-iinfo",
		"sucuri":      "x-sucuri",
		"f5":          "big-ip",
		"imperva":     "incap_ses",
		"modsecurity": "mod_security",
	}
	hay := strings.ToLower(string(resp.Body))
	for k, v := range resp.Headers {
		hay += strings.ToLower(k) + ":" + strings.ToLower(v[0]) + "\n"
	}
	for name, sig := range sigs {
		if strings.Contains(hay, sig) {
			found[name] = "detected"
		}
	}
	if len(found) == 0 {
		found["waf"] = "not detected (header-only fingerprint)"
	}
	return found
}