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
