package report

import (
	"encoding/csv"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// TestFindingTrafficMarkdownCoversStaleAttachmentsAndNoteEscaping exercises
// the branches go tool cover showed were missing (18.8%): the stale-evidence
// notice, the attachments-link branch, and — most importantly — that a
// binding's Note (operator-entered, but rendered the same as every other
// untrusted field) is actually escaped against Markdown injection, not just
// that the function runs without panicking.
func TestFindingTrafficMarkdownCoversStaleAttachmentsAndNoteEscaping(t *testing.T) {
	f := &db.DBFinding{
		ID:                    9,
		Report:                "existing report",
		EvidenceVersion:       3,
		ReportEvidenceVersion: 1, // differs from EvidenceVersion -> stale
		TrafficBindings: []db.FindingTrafficBinding{
			{
				ID:   101,
				Role: "proof",
				Note: "see [click me](http://attacker.tld) for details",
				Snapshot: db.TrafficEvidenceSnapshot{
					Method: "GET", URL: "https://target.example.com/a?x=`1`", Status: 200,
				},
			},
		},
	}

	withAttachments := findingTrafficMarkdown(f, true)
	if !strings.Contains(withAttachments, "The evidence has changed") {
		t.Errorf("stale notice missing:\n%s", withAttachments)
	}
	if !strings.Contains(withAttachments, "Request message") || !strings.Contains(withAttachments, "evidence/9/101/") {
		t.Errorf("attachment links missing:\n%s", withAttachments)
	}
	if strings.Contains(withAttachments, "[click me](http://attacker.tld)") {
		t.Errorf("binding note link injection not escaped:\n%s", withAttachments)
	}
	if !strings.Contains(withAttachments, `\[click me\]\(http://attacker.tld\)`) {
		t.Errorf("expected the note's [ ] ( ) escaped, got:\n%s", withAttachments)
	}
	// The URL's backtick must still be neutralized as %60 (pre-existing
	// inline-code-span defense, unrelated to mdEscapeText) so it cannot
	// close the single-backtick code span early.
	if !strings.Contains(withAttachments, "%601%60") {
		t.Errorf("URL backtick not neutralized:\n%s", withAttachments)
	}

	withoutAttachments := findingTrafficMarkdown(f, false)
	if strings.Contains(withoutAttachments, "Request message") {
		t.Errorf("attachments=false should omit the attachment links:\n%s", withoutAttachments)
	}

	// Not stale, no bindings -> empty (the function's early-return branch).
	fresh := &db.DBFinding{ID: 1, EvidenceVersion: 1, ReportEvidenceVersion: 1}
	if got := findingTrafficMarkdown(fresh, false); got != "" {
		t.Errorf("no bindings and not stale should render nothing, got %q", got)
	}
}

// TestFindingFilenameNeverEscapesTheTargetDirectory is the actual zip-slip
// regression: a model-reported Name/VulnClass (untrusted, same provenance as
// every other injection fix this session) must never produce a filename
// that, once joined with the extraction/zip target directory, resolves
// outside it.
func TestFindingFilenameNeverEscapesTheTargetDirectory(t *testing.T) {
	payloads := []string{
		"../../etc/passwd",
		"..\\..\\windows\\system32\\evil.dll",
		"....//....//etc/passwd",
		"/etc/passwd",
		strings.Repeat("../", 20) + "evil",
	}
	for _, p := range payloads {
		f := &db.DBFinding{ID: 1, Name: p, Severity: "high"}
		name := FindingFilename(f)
		if strings.ContainsAny(name, `/\`) {
			t.Errorf("Name=%q: filename %q still contains a path separator", p, name)
		}
		joined := filepath.Clean(filepath.Join("/safe/export/dir", name))
		if !strings.HasPrefix(joined, "/safe/export/dir") {
			t.Errorf("Name=%q: filename %q escapes the target directory, joined=%q", p, name, joined)
		}
	}
}

// TestFindingFilenameTruncationStaysValidUTF8 is the bug coverage analysis
// surfaced directly: the allowed filename charset includes any Unicode
// letter (\p{L}, \p{Han} explicitly), so the old s[:120] byte-slice
// truncation could cut a multi-byte rune in half and produce an invalid
// UTF-8 filename. Misaligns the cut point deliberately (varying prefix
// length) to make sure at least one case would have landed mid-rune under
// the old code.
func TestFindingFilenameTruncationStaysValidUTF8(t *testing.T) {
	for extra := 0; extra < 3; extra++ {
		name := strings.Repeat("x", extra) + strings.Repeat("漏", 60) // "漏" x60, shifted by 0/1/2 ASCII chars
		f := &db.DBFinding{ID: 42, Name: name, Severity: "high"}
		got := FindingFilename(f)
		if !utf8.ValidString(got) {
			t.Errorf("extra=%d: truncated filename is not valid UTF-8: %q", extra, got)
		}
		if !strings.HasSuffix(got, ".md") {
			t.Errorf("extra=%d: filename must still end in .md: %q", extra, got)
		}
	}
}

// TestFindingFilenameHandlesAllPunctuationTitle covers a title made entirely
// of characters the sanitizer strips to "_": the finding id (always a
// trailing run of digits, never trimmed by the "._" cutset) guarantees the
// result is never empty even when the title contributes nothing readable.
func TestFindingFilenameHandlesAllPunctuationTitle(t *testing.T) {
	f := &db.DBFinding{ID: 7, Name: "???###!!!"}
	got := FindingFilename(f)
	if got == "" || got == ".md" {
		t.Fatalf("an all-punctuation title should still produce a non-empty filename, got %q", got)
	}
	if !strings.Contains(got, "7") {
		t.Fatalf("filename should carry the finding id, got %q", got)
	}
	if !strings.HasSuffix(got, ".md") {
		t.Fatalf("filename should end in .md, got %q", got)
	}
}
