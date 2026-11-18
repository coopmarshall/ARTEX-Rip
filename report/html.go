package report

import (
	"html/template"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// FindingsHTML renders a batch of findings as a single, self-contained HTML
// file: a severity summary table followed by one section per finding, with
// inline CSS so the output needs no other files to view or share.
//
// Unlike FindingsMarkdown/FindingsCSV (which must escape every untrusted
// field by hand — see mdEscapeText/csvFormulaGuard and the injection fixes
// earlier this session), html/template auto-escapes every {{.Field}}
// interpolation by construction: there is no manual-escaping call to
// forget here, and a finding Name/Summary/Evidence containing
// `<script>` or `"><img onerror=...>` renders as inert text, not markup.
// DBFinding.Report is still the one exception: it is the agent's own
// authored Markdown, not HTML, so rendering it as literal text (inside a
// <pre>) is correct — turning it into live HTML would need a Markdown
// renderer, out of scope here, and auto-escaping already makes that
// omission safe either way.
func FindingsHTML(fs []*db.DBFinding, generatedAt time.Time) (string, error) {
	items := append([]*db.DBFinding(nil), fs...)
	sortFindingsForExport(items)

	counts := map[string]int{}
	for _, f := range items {
		counts[f.Severity]++
	}

	data := htmlReportData{
		GeneratedAt: generatedAt.Format("2006-01-02 15:04:05"),
		Total:       len(items),
		Counts: []htmlSevCount{
			{Label: "Critical", Key: "critical", Count: counts["critical"]},
			{Label: "High", Key: "high", Count: counts["high"]},
			{Label: "Medium", Key: "medium", Count: counts["medium"]},
			{Label: "Low", Key: "low", Count: counts["low"]},
		},
	}
	maxCount := 0
	for _, c := range data.Counts {
		if c.Count > maxCount {
			maxCount = c.Count
		}
	}
	for i := range data.Counts {
		if maxCount > 0 {
			data.Counts[i].BarPercent = data.Counts[i].Count * 100 / maxCount
		}
	}
	for _, f := range items {
		data.Findings = append(data.Findings, htmlFindingView{
			Title:            findingTitle(f),
			Severity:         f.Severity,
			SeverityLabel:    strings.ToUpper(nz(f.Severity, "info")),
			Class:            f.VulnClass,
			Status:           nz(f.Status, "pending"),
			Verification:     verificationLabel(f),
			VerificationNote: strings.TrimSpace(f.VerificationNote),
			Counterevidence:  strings.TrimSpace(f.Counterevidence),
			Confidence:       strings.TrimSpace(f.ConfidenceRationale),
			Task:             strings.TrimSpace(f.TaskDescription),
			FoundAt:          f.CreatedAt.Format("2006-01-02 15:04:05"),
			Summary:          strings.TrimSpace(f.Summary),
			Evidence:         strings.TrimSpace(f.Evidence),
			Report:           strings.TrimSpace(f.Report),
		})
	}

	var b strings.Builder
	if err := htmlReportTemplate.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

type htmlSevCount struct {
	Label, Key string
	Count      int
	BarPercent int // 0-100, relative to the largest count shown, for the summary bar chart
}

type htmlFindingView struct {
	Title, Severity, SeverityLabel, Class, Status               string
	Verification, VerificationNote, Counterevidence, Confidence string
	Task, FoundAt, Summary, Evidence, Report                    string
}

type htmlReportData struct {
	GeneratedAt string
	Total       int
	Counts      []htmlSevCount
	Findings    []htmlFindingView
}

var htmlReportTemplate = template.Must(template.New("findings").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulnerability Findings Summary Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 960px; color: #1a1a1a; line-height: 1.5; }
  h1 { font-size: 1.5rem; }
  h2 { font-size: 1.1rem; border-bottom: 1px solid #ddd; padding-bottom: .3rem; margin-top: 2rem; }
  table.summary { border-collapse: collapse; margin: 1rem 0; }
  table.summary td { padding: .3rem .8rem; border: 1px solid #ddd; }
  table.summary td.bar-cell { border: none; padding: .3rem .8rem .3rem 0; }
  .bar-track { display: inline-block; width: 160px; height: 10px; background: #eee; border-radius: 3px; overflow: hidden; vertical-align: middle; }
  .bar-fill { height: 100%; }
  .bar-fill.sev-critical { background: #b00020; }
  .bar-fill.sev-high { background: #d2691e; }
  .bar-fill.sev-medium { background: #b8860b; }
  .bar-fill.sev-low { background: #2e6da4; }
  .finding { border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.2rem; margin: 1rem 0; }
  .meta { color: #555; font-size: .9rem; margin: .2rem 0; }
  .meta b { color: #1a1a1a; }
  pre { background: #f6f6f6; padding: .8rem; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
  .sev-critical { color: #b00020; }
  .sev-high { color: #d2691e; }
  .sev-medium { color: #b8860b; }
  .sev-low { color: #2e6da4; }
  @media print {
    /* There is no native PDF export; printing this page (Ctrl/Cmd+P -> Save as PDF)
       is the supported path, so it needs to look right as a document, not a webpage. */
    * { -webkit-print-color-adjust: exact; print-color-adjust: exact; color-adjust: exact; }
    body { margin: 0; max-width: none; }
    .finding { page-break-inside: avoid; border-color: #999; }
    h2 { page-break-after: avoid; }
    pre { white-space: pre-wrap; }
  }
</style>
</head>
<body>
<h1>Vulnerability Findings Summary Report</h1>
<p class="meta"><b>Generated at</b>: {{.GeneratedAt}} &middot; <b>Total findings</b>: {{.Total}}</p>
<table class="summary">
{{range .Counts}}<tr><td class="sev-{{.Key}}">{{.Label}}</td><td>{{.Count}}</td><td class="bar-cell"><span class="bar-track"><span class="bar-fill sev-{{.Key}}" style="width:{{.BarPercent}}%"></span></span></td></tr>
{{end}}</table>
{{if eq .Total 0}}<p><em>No matching vulnerabilities.</em></p>{{end}}
{{range $i, $f := .Findings}}
<div class="finding">
  <h2><span class="sev-{{$f.Severity}}">[{{$f.SeverityLabel}}]</span> {{$f.Title}}</h2>
  {{if $f.Class}}<p class="meta"><b>Class</b>: {{$f.Class}}</p>{{end}}
  <p class="meta"><b>Status</b>: {{$f.Status}}</p>
  <p class="meta"><b>Verification</b>: {{$f.Verification}}</p>
  {{if $f.VerificationNote}}<p class="meta"><b>Verification note</b>: {{$f.VerificationNote}}</p>{{end}}
  {{if $f.Counterevidence}}<p class="meta"><b>Counterevidence</b>: {{$f.Counterevidence}}</p>{{end}}
  {{if $f.Confidence}}<p class="meta"><b>Confidence rationale</b>: {{$f.Confidence}}</p>{{end}}
  {{if $f.Task}}<p class="meta"><b>Task</b>: {{$f.Task}}</p>{{end}}
  <p class="meta"><b>Found at</b>: {{$f.FoundAt}}</p>
  {{if $f.Summary}}<p>{{$f.Summary}}</p>{{end}}
  {{if $f.Evidence}}<p class="meta"><b>Evidence</b>:</p><pre>{{$f.Evidence}}</pre>{{end}}
  {{if $f.Report}}<p class="meta"><b>Detailed report</b> (Markdown, shown as text):</p><pre>{{$f.Report}}</pre>{{end}}
</div>
{{end}}
</body>
</html>
`))
