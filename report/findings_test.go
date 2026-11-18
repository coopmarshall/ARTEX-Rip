package report

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestFindingsCSVIncludesVerificationFields locks in that the CSV export
// carries the same POE/verification summary fields as the SARIF and JSON
// exports (#S1 verified findings), so a reviewer working from the CSV is not
// missing the one signal that distinguishes a proven finding from a lead.
// Long free text (report/evidence/verification note) stays out on purpose —
// see the FindingsCSV doc comment — this only checks the short fields.
func TestFindingsCSVIncludesVerificationFields(t *testing.T) {
	f := &db.DBFinding{
		ID:                 42,
		Name:               "login page SQL injection",
		Severity:           "high",
		Status:             "confirmed",
		PoELevel:           3,
		VerificationStatus: "verified",
		CreatedAt:          time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	raw := FindingsCSV([]*db.DBFinding{f})
	// Strip the UTF-8 BOM before handing the bytes to encoding/csv.
	body := strings.TrimPrefix(string(raw), "\xEF\xBB\xBF")
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v\n%s", err, body)
	}
	if len(rows) != 2 {
		t.Fatalf("expected a header row + 1 data row, got %d rows", len(rows))
	}
	header, data := rows[0], rows[1]

	col := func(name string) string {
		for i, h := range header {
			if h == name {
				return data[i]
			}
		}
		t.Fatalf("column %q not found in header %v", name, header)
		return ""
	}
	if got := col("PoE Level"); got != "3" {
		t.Errorf("PoE Level = %q, want 3", got)
	}
	if got := col("Verification Status"); got != "verified" {
		t.Errorf("Verification Status = %q, want verified", got)
	}
}

// TestFindingsCSVDefaultsUnassessedVerification covers a finding predating the
// verified-findings feature (zero PoELevel, empty VerificationStatus): it must
// read as "not_assessed", not blank, so a spreadsheet filter cannot confuse
// "never checked" with an empty cell from a parsing bug.
func TestFindingsCSVDefaultsUnassessedVerification(t *testing.T) {
	f := &db.DBFinding{ID: 1, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	body := strings.TrimPrefix(string(FindingsCSV([]*db.DBFinding{f})), "\xEF\xBB\xBF")
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v", err)
	}
	header, data := rows[0], rows[1]
	for i, h := range header {
		if h == "Verification Status" && data[i] != "not_assessed" {
			t.Errorf("Verification Status = %q, want not_assessed", data[i])
		}
		if h == "PoE Level" && data[i] != "0" {
			t.Errorf("PoE Level = %q, want 0", data[i])
		}
	}
}

// TestFindingsCSVGuardsAgainstFormulaInjection is the end-to-end regression
// for CWE-1236 on the one export format that was still exposed to it: a
// finding whose model-reported Name/Class/Summary happens to start with a
// formula-triggering character must not reach the CSV cell unguarded.
func TestFindingsCSVGuardsAgainstFormulaInjection(t *testing.T) {
	f := &db.DBFinding{
		ID:              1,
		Name:            "=HYPERLINK(\"http://attacker.tld\",\"click\")",
		VulnClass:       "+malicious",
		TaskDescription: "@SUM(A1:A9)",
		Summary:         "-1+1",
		CreatedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	body := strings.TrimPrefix(string(FindingsCSV([]*db.DBFinding{f})), "\xEF\xBB\xBF")
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v", err)
	}
	data := rows[1]
	header := rows[0]
	col := func(name string) string {
		for i, h := range header {
			if h == name {
				return data[i]
			}
		}
		t.Fatalf("column %q not found", name)
		return ""
	}
	for _, c := range []struct{ name, want string }{
		{"Name", "'=HYPERLINK(\"http://attacker.tld\",\"click\")"},
		{"Class", "'+malicious"},
		{"Task", "'@SUM(A1:A9)"},
		{"Summary", "'-1+1"},
	} {
		if got := col(c.name); got != c.want {
			t.Errorf("column %s = %q, want %q (formula-guarded)", c.name, got, c.want)
		}
	}
}

// TestVerificationLabelMatchesBadgeWording locks in that the Markdown export
// uses the exact same five-state wording as the findings-page verification
// badge (0.6.0: "Verified L3/L4", "Unverified", "Blocked", "Not assessed",
// "False positive"), so a reader is never shown two different vocabularies
// for the same state depending on which export they open.
func TestVerificationLabelMatchesBadgeWording(t *testing.T) {
	cases := []struct {
		status string
		poe    int
		want   string
	}{
		{"verified", 3, "Verified L3"},
		{"verified", 4, "Verified L4"},
		{"unverified", 0, "Unverified"},
		{"blocked", 0, "Blocked"},
		{"false_positive", 0, "False positive"},
		{"not_assessed", 0, "Not assessed"},
		{"", 0, "Not assessed"},
	}
	for _, tc := range cases {
		f := &db.DBFinding{VerificationStatus: tc.status, PoELevel: tc.poe}
		if got := verificationLabel(f); got != tc.want {
			t.Errorf("status=%q poe=%d: got %q, want %q", tc.status, tc.poe, got, tc.want)
		}
	}
}

// TestFindingsMarkdownIncludesVerificationFields covers both Markdown export
// functions (the summary batch and the single-finding standalone file): a
// reviewer reading either must see the verification state and, when present,
// the note/counterevidence/confidence rationale — not just in the SARIF/CSV
// exports.
func TestFindingsMarkdownIncludesVerificationFields(t *testing.T) {
	f := &db.DBFinding{
		ID: 1, Name: "IDOR", Severity: "high",
		PoELevel: 3, VerificationStatus: "verified",
		VerificationNote:    "replayed with a second account",
		Counterevidence:     "rate limiting did not block the replay",
		ConfidenceRationale: "response bodies differ only by the target user's own data",
		CreatedAt:           time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

	for name, out := range map[string]string{
		"FindingsMarkdown":      FindingsMarkdown([]*db.DBFinding{f}, now),
		"SingleFindingMarkdown": SingleFindingMarkdown(f, now),
	} {
		if !strings.Contains(out, "Verified L3") {
			t.Errorf("%s: missing verification label:\n%s", name, out)
		}
		if !strings.Contains(out, "replayed with a second account") {
			t.Errorf("%s: missing verification note:\n%s", name, out)
		}
		if !strings.Contains(out, "rate limiting did not block the replay") {
			t.Errorf("%s: missing counterevidence:\n%s", name, out)
		}
		if !strings.Contains(out, "response bodies differ only by the target user's own data") {
			t.Errorf("%s: missing confidence rationale:\n%s", name, out)
		}
	}
}

// TestFindingsMarkdownOmitsEmptyVerificationDetails covers the common legacy
// case: a finding with no note/counterevidence/rationale must render just
// the one "Not assessed" bullet, not three empty "- **X**: " lines.
func TestFindingsMarkdownOmitsEmptyVerificationDetails(t *testing.T) {
	f := &db.DBFinding{ID: 1, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	out := SingleFindingMarkdown(f, time.Now())
	if !strings.Contains(out, "- **Verification**: Not assessed\n") {
		t.Errorf("missing the Not assessed line:\n%s", out)
	}
	for _, label := range []string{"Verification note", "Counterevidence", "Confidence rationale"} {
		if strings.Contains(out, label) {
			t.Errorf("empty %s field should not render a bullet:\n%s", label, out)
		}
	}
}

// TestFindingsMarkdownEscapesUntrustedFieldsButNotReport is the end-to-end
// regression for the Markdown-injection gap: Name/VulnClass/Summary come
// straight from the model's report_finding call, shaped by whatever the
// scanned target returned, so a crafted title must not survive as a live
// link/image in whatever Markdown viewer the exported .md is later opened
// in. DBFinding.Report, by contrast, is the agent's own authored Markdown
// report and must render verbatim — escaping it would turn its intended
// headings/emphasis into visible backslash litter.
func TestFindingsMarkdownEscapesUntrustedFieldsButNotReport(t *testing.T) {
	f := &db.DBFinding{
		ID:        1,
		Name:      "XSS\n[URGENT: verify your account](http://attacker.tld)",
		VulnClass: "![beacon](http://attacker.tld/b.png)",
		Severity:  "high",
		Summary:   "clicking *here* triggers the payload",
		Report:    "## Root cause\n\nThe `id` parameter is not sanitized.",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

	for name, out := range map[string]string{
		"FindingsMarkdown":      FindingsMarkdown([]*db.DBFinding{f}, now),
		"SingleFindingMarkdown": SingleFindingMarkdown(f, now),
	} {
		if strings.Contains(out, "](http://attacker.tld)") {
			t.Errorf("%s: link injection from Name not neutralized:\n%s", name, out)
		}
		if strings.Contains(out, "![beacon](http://attacker.tld/b.png)") {
			t.Errorf("%s: image/beacon injection from VulnClass not neutralized:\n%s", name, out)
		}
		if strings.Contains(out, "clicking *here* triggers") {
			t.Errorf("%s: emphasis injection from Summary not neutralized:\n%s", name, out)
		}
		// The agent's own authored report must render verbatim, unescaped.
		if !strings.Contains(out, "## Root cause") || !strings.Contains(out, "The `id` parameter is not sanitized.") {
			t.Errorf("%s: Report field was altered, should render verbatim:\n%s", name, out)
		}
	}
}

// TestFindingsMarkdownEvidenceFenceSurvivesEmbeddedBackticks covers the
// code-fence breakout: untrusted Evidence containing its own "```" must not
// be able to close the fence early and leak the remainder as live Markdown.
func TestFindingsMarkdownEvidenceFenceSurvivesEmbeddedBackticks(t *testing.T) {
	f := &db.DBFinding{
		ID:        2,
		Name:      "RCE",
		Severity:  "critical",
		Evidence:  "captured response:\n```\nmalicious payload\n```\n[click me](http://attacker.tld)",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	out := SingleFindingMarkdown(f, time.Now())
	// The embedded "[click me](...)" sits inside what must still be fenced
	// code; it should appear verbatim as code, not escaped (fences protect
	// content without needing character escaping) but must not have become
	// live Markdown by escaping out of the block early.
	idx := strings.Index(out, "[click me](http://attacker.tld)")
	if idx < 0 {
		t.Fatalf("evidence content missing from output:\n%s", out)
	}
	// Everything up to and including that text must still be inside a fence
	// opened with 4+ backticks (mdCodeFence's answer for a body containing a
	// run of 3).
	if !strings.Contains(out[:idx], "````") {
		t.Fatalf("evidence fence was not widened past the embedded ``` run:\n%s", out)
	}
}
