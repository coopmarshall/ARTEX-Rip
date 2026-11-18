package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestFindingsHTMLNoFindingsSaysSo(t *testing.T) {
	out, err := FindingsHTML(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "No matching vulnerabilities") {
		t.Errorf("empty findings should say so explicitly:\n%s", out)
	}
	if !strings.Contains(out, "Total findings</b>: 0") {
		t.Errorf("summary count wrong:\n%s", out)
	}
}

func TestFindingsHTMLSortsBySeverityDescending(t *testing.T) {
	fs := []*db.DBFinding{
		{ID: 1, Name: "low finding", Severity: "low", CreatedAt: time.Now()},
		{ID: 2, Name: "critical finding", Severity: "critical", CreatedAt: time.Now()},
		{ID: 3, Name: "medium finding", Severity: "medium", CreatedAt: time.Now()},
	}
	out, err := FindingsHTML(fs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	critIdx := strings.Index(out, "critical finding")
	medIdx := strings.Index(out, "medium finding")
	lowIdx := strings.Index(out, "low finding")
	if !(critIdx > 0 && critIdx < medIdx && medIdx < lowIdx) {
		t.Fatalf("findings not sorted critical > medium > low, positions %d/%d/%d:\n%s", critIdx, medIdx, lowIdx, out)
	}
}

// TestFindingsHTMLEscapesUntrustedContent is the actual point of this export
// format: unlike the Markdown/CSV exports (which need mdEscapeText /
// csvFormulaGuard called by hand), html/template auto-escapes every
// {{.Field}} by construction. This locks in that guarantee with the same
// payloads the Markdown-injection fix used earlier this session, now
// targeting script/attribute injection instead of link/image injection.
func TestFindingsHTMLEscapesUntrustedContent(t *testing.T) {
	f := &db.DBFinding{
		ID:        1,
		Name:      `<script>alert(1)</script>`,
		VulnClass: `"><img src=x onerror=alert(2)>`,
		Severity:  "high",
		Summary:   `a & b < c "quoted"`,
		Evidence:  `</pre><script>alert(3)</script>`,
		CreatedAt: time.Now(),
	}
	out, err := FindingsHTML([]*db.DBFinding{f}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, dangerous := range []string{
		"<script>alert(1)</script>",
		`"><img src=x onerror=alert(2)>`,
		"</pre><script>alert(3)</script>",
	} {
		if strings.Contains(out, dangerous) {
			t.Errorf("untrusted content rendered live, not escaped: %q found verbatim in output", dangerous)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("expected the Name to be HTML-escaped, got:\n%s", out)
	}
	if !strings.Contains(out, "a &amp; b &lt; c &#34;quoted&#34;") {
		t.Errorf("expected the Summary to be HTML-escaped, got:\n%s", out)
	}
}

// TestFindingsHTMLRendersReportAsLiteralText covers the one deliberate
// non-escaping-related choice: DBFinding.Report is the agent's own
// Markdown, not HTML, so it must appear as readable text (inside <pre>,
// still auto-escaped) rather than attempting to render Markdown as HTML.
func TestFindingsHTMLRendersReportAsLiteralText(t *testing.T) {
	f := &db.DBFinding{ID: 1, Name: "X", Severity: "low", Report: "## Root cause\n\nThe `id` param is unsanitized.", CreatedAt: time.Now()}
	out, err := FindingsHTML([]*db.DBFinding{f}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "## Root cause") {
		t.Errorf("Report should render as literal text (including Markdown syntax), got:\n%s", out)
	}
	if strings.Contains(out, "<h2>Root cause</h2>") {
		t.Errorf("Report must not be rendered as live HTML, got:\n%s", out)
	}
}

func TestFindingsHTMLIsWellFormed(t *testing.T) {
	fs := []*db.DBFinding{{ID: 1, Name: "X", Severity: "high", CreatedAt: time.Now()}}
	out, err := FindingsHTML(fs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Errorf("should start with a doctype, got:\n%.50s", out)
	}
	if strings.Count(out, "<html") != 1 || !strings.Contains(out, "</html>") {
		t.Errorf("malformed document:\n%s", out)
	}
}

func TestFindingsHTMLSeverityBarsScaleToTheLargestCount(t *testing.T) {
	fs := []*db.DBFinding{
		{ID: 1, Severity: "critical", CreatedAt: time.Now()},
		{ID: 2, Severity: "critical", CreatedAt: time.Now()},
		{ID: 3, Severity: "low", CreatedAt: time.Now()},
	}
	out, err := FindingsHTML(fs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ sev, want string }{
		{"critical", `width:100%`}, // the largest count (2) fills the bar
		{"high", `width:0%`},       // zero findings -> zero-width bar, not omitted
		{"medium", `width:0%`},
		{"low", `width:50%`}, // 1 of a max of 2
	}
	for _, c := range cases {
		marker := `bar-fill sev-` + c.sev + `" style="` + c.want
		if !strings.Contains(out, marker) {
			t.Errorf("expected %q in output for severity %q, not found", marker, c.sev)
		}
	}
}

// TestFindingsHTMLHasPrintStylesheet covers the only path to a PDF-like
// document (browser Print -> Save as PDF, there being no native PDF
// export): page breaks must not split a finding block, and print color
// adjustment must be forced on so the severity bars don't vanish (Chrome
// drops CSS background colors on print by default).
func TestFindingsHTMLHasPrintStylesheet(t *testing.T) {
	out, err := FindingsHTML(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"@media print", "page-break-inside: avoid", "print-color-adjust: exact"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the stylesheet, not found", want)
		}
	}
}

func TestFindingsHTMLSeverityBarsAllZeroWhenNoFindings(t *testing.T) {
	out, err := FindingsHTML(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "NaN") || strings.Contains(out, "+Inf") {
		t.Fatalf("zero findings should not divide by zero in the bar percentage calc:\n%s", out)
	}
	if !strings.Contains(out, `style="width:0%"`) {
		t.Errorf("expected all-zero bars with no findings, got:\n%s", out)
	}
}
