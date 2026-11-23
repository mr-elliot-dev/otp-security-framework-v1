package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

type Severity string

const (
	Info   Severity = "Info"
	Low    Severity = "Low"
	Medium Severity = "Medium"
	High   Severity = "High"
)

type Finding struct {
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation,omitempty"`
}

type Report struct {
	ID            string         `json:"id"`
	Generated     time.Time      `json:"generated"`
	Target        string         `json:"target"`
	Sections      map[string]any `json:"sections"`
	Findings      []Finding      `json:"findings"`
	OverallRating Severity       `json:"overall_rating"`
}

func New(target string) *Report {
	return &Report{
		ID:        uuid.NewString(),
		Generated: time.Now().UTC(),
		Target:    target,
		Sections:  map[string]any{},
	}
}

func (r *Report) Add(title string, sev Severity, detail, remediation string) {
	r.Findings = append(r.Findings, Finding{Title: title, Severity: sev, Detail: detail, Remediation: remediation})
	if severityRank(sev) > severityRank(r.OverallRating) {
		r.OverallRating = sev
	}
}

func severityRank(s Severity) int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

func (r *Report) WriteJSON(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("report-%s.json", r.ID))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return path, enc.Encode(r)
}

const htmlTpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>OTP Security Report</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;background:#0b0f14;color:#e7eef7}
h1{color:#66d9ef}.sev-High{color:#ff5c5c}.sev-Medium{color:#ffb454}.sev-Low{color:#9ece6a}.sev-Info{color:#7aa2f7}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th,td{border:1px solid #263041;padding:0.6rem;text-align:left;vertical-align:top}
code{background:#1a2230;padding:2px 6px;border-radius:4px}
</style></head><body>
<h1>OTP Security Testing Report</h1>
<p><strong>Report ID:</strong> {{.ID}}<br>
<strong>Target:</strong> <code>{{.Target}}</code><br>
<strong>Generated:</strong> {{.Generated}}<br>
<strong>Overall Rating:</strong> <span class="sev-{{.OverallRating}}">{{.OverallRating}}</span></p>
<h2>Findings</h2>
<table><tr><th>#</th><th>Severity</th><th>Title</th><th>Detail</th><th>Remediation</th></tr>
{{range $i,$f := .Findings}}<tr><td>{{$i}}</td>
<td class="sev-{{$f.Severity}}">{{$f.Severity}}</td>
<td>{{$f.Title}}</td><td>{{$f.Detail}}</td><td>{{$f.Remediation}}</td></tr>{{end}}
</table>
<h2>Raw Data</h2>
<pre>{{.SectionsJSON}}</pre>
</body></html>`

func (r *Report) WriteHTML(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	raw, _ := json.MarshalIndent(r.Sections, "", "  ")
	data := struct {
		*Report
		SectionsJSON string
	}{r, string(raw)}

	path := filepath.Join(dir, fmt.Sprintf("report-%s.html", r.ID))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	t := template.Must(template.New("r").Parse(htmlTpl))
	return path, t.Execute(f, data)
}