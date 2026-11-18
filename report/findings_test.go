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
