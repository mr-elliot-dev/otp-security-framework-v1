package otp

import (
	"context"
	"errors"
	"time"

	"github.com/yourorg/otpsec/internal/httpclient"
)

// ReplayTest attempts the same synthetic OTP twice to check replay protection.
// Real OTPs are never used — caller supplies synthetic value from a local lab.
func ReplayTest(ctx context.Context, c *httpclient.Client, verifyURL, syntheticOTP string) (bool, error) {
	body := []byte(`{"otp":"` + syntheticOTP + `"}`)
	r1, err := c.Do(ctx, "POST", verifyURL, bytesReader(body))
	if err != nil {
		return false, err
	}
	time.Sleep(300 * time.Millisecond)
	r2, err := c.Do(ctx, "POST", verifyURL, bytesReader(body))
	if err != nil {
		return false, err
	}
	// If both return identical 200 success, replay protection is likely absent.
	if r1.StatusCode == 200 && r2.StatusCode == 200 {
		return false, errors.New("suspected replay: identical success on reuse")
	}
	return true, nil
}

// ExpirationTest is a timing-based heuristic; does not brute-force.
func ExpirationTest(ctx context.Context, c *httpclient.Client, verifyURL, syntheticOTP string, wait time.Duration) (bool, error) {
	body := []byte(`{"otp":"` + syntheticOTP + `"}`)
	_, _ = c.Do(ctx, "POST", verifyURL, bytesReader(body))
	select {
	case <-time.After(wait):
	case <-ctx.Done():
		return false, ctx.Err()
	}
	resp, err := c.Do(ctx, "POST", verifyURL, bytesReader(body))
	if err != nil {
		return false, err
	}
	// If expired OTP still returns 200, expiration is not enforced.
	return resp.StatusCode != 200, nil
}