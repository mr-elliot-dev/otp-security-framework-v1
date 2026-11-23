package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yourorg/otpsec/internal/analyzer"
	"github.com/yourorg/otpsec/internal/config"
	"github.com/yourorg/otpsec/internal/csrf"
	"github.com/yourorg/otpsec/internal/endpoint"
	"github.com/yourorg/otpsec/internal/httpclient"
	"github.com/yourorg/otpsec/internal/otp"
	"github.com/yourorg/otpsec/internal/ratelimit"
	"github.com/yourorg/otpsec/internal/reporter"
	"github.com/yourorg/otpsec/internal/session"
	"github.com/yourorg/otpsec/internal/waf"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "analyze":
		runAnalyze(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Println(`otpsec — authorized OTP security testing
Usage:
  otpsec scan    --target http://localhost:8080 --config config/config.json
  otpsec analyze --target http://localhost:8080
  otpsec report  --format html`)
}

func mustConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(2)
	}
	return cfg
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	target := fs.String("target", "", "target base URL")
	cfgPath := fs.String("config", "config/config.json", "config path")
	_ = fs.Parse(args)

	cfg := mustConfig(*cfgPath)
	if *target != "" {
		cfg.Target = *target
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "refusing:", err)
		os.Exit(3)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := httpclient.New(cfg.Timeout, cfg.UserAgent)
	rep := reporter.New(cfg.Target)

	// 1) Discovery
	disc := endpoint.Discover(ctx, client, cfg.Target)
	rep.Sections["discovery"] = disc

	// 2) Header analysis
	base, err := client.Do(ctx, "GET", cfg.Target, nil)
	if err == nil {
		rep.Sections["base_status"] = base.StatusCode
		for _, r := range analyzer.AnalyzeHeaders(base.Headers) {
			rep.Add(r.Title, reporter.Severity(r.Severity), r.Detail,
				"Set the missing security header.")
		}
		rep.Sections["csrf"] = csrf.Analyze(base)
		rep.Sections["session"] = session.Analyze(base, nil)
	} else {
		rep.Add("Target unreachable", reporter.High, err.Error(), "Verify target URL.")
	}

	// 3) WAF fingerprint
	rep.Sections["waf"] = waf.Fingerprint(ctx, client, cfg.Target)

	// 4) Rate-limit probe (bounded, throttled)
	if cfg.MaxRequests > 0 {
		rl := ratelimit.Probe(ctx, client, cfg.Target, cfg.MaxRequests, cfg.RequestsPerSecond)
		rep.Sections["rate_limit"] = rl
		if hit, _ := rl["rate_limit_hit"].(bool); !hit {
			rep.Add("No rate limiting observed", reporter.Medium,
				fmt.Sprintf("%d requests with no 429 responses", cfg.MaxRequests),
				"Add per-IP and per-account rate limits on OTP endpoints.")
		}
	}

	// 5) OTP replay/expiration (only if verify endpoint configured)
	if cfg.VerifyEndpoint != "" {
		if ok, err := otp.ReplayTest(ctx, client, cfg.VerifyEndpoint, "000000"); err == nil && !ok {
			rep.Add("Possible OTP replay", reporter.High, "Same synthetic OTP accepted twice",
				"Invalidate OTPs after use; bind OTP to session + single use.")
		}
		if ok, err := otp.ExpirationTest(ctx, client, cfg.VerifyEndpoint, "000000", 2*time.Minute); err == nil && !ok {
			rep.Add("OTP expiration not enforced", reporter.High, "OTP still accepted after 2 min",
				"Set OTP TTL to <= 5 minutes and enforce server-side.")
		}
	}

	// 6) Reports
	jsonPath, _ := rep.WriteJSON(cfg.ReportDir)
	htmlPath, _ := rep.WriteHTML(cfg.ReportDir)
	fmt.Println("JSON report:", jsonPath)
	fmt.Println("HTML report:", htmlPath)
	fmt.Println("Overall:", rep.OverallRating)
}

func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	target := fs.String("target", "", "target base URL")
	cfgPath := fs.String("config", "config/config.json", "config path")
	_ = fs.Parse(args)
	cfg := mustConfig(*cfgPath)
	if *target != "" {
		cfg.Target = *target
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "refusing:", err)
		os.Exit(3)
	}
	client := httpclient.New(cfg.Timeout, cfg.UserAgent)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	resp, err := client.Do(ctx, "GET", cfg.Target, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("Status:", resp.StatusCode)
	for _, r := range analyzer.AnalyzeHeaders(resp.Headers) {
		fmt.Printf("[%s] %s — %s\n", r.Severity, r.Title, r.Detail)
	}
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	format := fs.String("format", "html", "html|json")
	_ = fs.Parse(args)
	fmt.Printf("Use `otpsec scan` to generate reports. Requested format: %s\n", *format)
}