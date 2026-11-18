package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func sarifFinding(id int64, vulnClass, severity string) *db.DBFinding {
	return &db.DBFinding{
		ID:        id,
		VulnClass: vulnClass,
		Severity:  severity,
		Summary:   "summary for " + vulnClass,
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// TestSARIFIsValidJSONWithSchemaAndVersion locks in the two fields every SARIF
// consumer checks before doing anything else with the file.
func TestSARIFIsValidJSONWithSchemaAndVersion(t *testing.T) {
	raw := FindingsSARIF([]*db.DBFinding{sarifFinding(1, "SQL Injection", "high")})
	var out sarifLog
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, raw)
	}
	if out.Schema != sarifSchema {
		t.Errorf("wrong $schema: %q", out.Schema)
	}
	if out.Version != sarifVersion {
		t.Errorf("wrong version: %q", out.Version)
	}
	if len(out.Runs) != 1 {
		t.Fatalf("expected exactly one run, got %d", len(out.Runs))
	}
	if out.Runs[0].Tool.Driver.Name != "ARTEX" {
		t.Errorf("wrong tool name: %q", out.Runs[0].Tool.Driver.Name)
	}
}

// TestSARIFDedupesRulesByVulnClass is the actual point of using SARIF's
// rule/result split: many findings of the same class must collapse onto one
// rule, not one rule per finding.
func TestSARIFDedupesRulesByVulnClass(t *testing.T) {
	fs := []*db.DBFinding{
		sarifFinding(1, "SQL Injection", "high"),
		sarifFinding(2, "SQL Injection", "critical"),
		sarifFinding(3, "XSS", "medium"),
	}
	var out sarifLog
	if err := json.Unmarshal(FindingsSARIF(fs), &out); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	rules := out.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 distinct rules (SQLi, XSS), got %d: %+v", len(rules), rules)
	}
	results := out.Runs[0].Results
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	// Every result's ruleIndex must point at a rule actually carrying its ruleId.
	for _, r := range results {
		if r.RuleIndex < 0 || r.RuleIndex >= len(rules) {
			t.Fatalf("ruleIndex %d out of range for result %q", r.RuleIndex, r.RuleID)
		}
		if rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("result %q: ruleIndex %d points at rule %q, want %q", r.RuleID, r.RuleIndex, rules[r.RuleIndex].ID, r.RuleID)
		}
	}
}

// TestSARIFSeverityMapsToLevel covers the one piece of domain logic a
// consumer actually branches on: which bucket (error/warning/note) a result
// lands in, since that drives default-view filtering in most SARIF viewers.
func TestSARIFSeverityMapsToLevel(t *testing.T) {
	cases := []struct {
		severity string
		level    string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"", "warning"},
		{"something-unexpected", "warning"},
	}
	for _, tc := range cases {
		if got := sarifLevel(tc.severity); got != tc.level {
			t.Errorf("severity %q: got level %q, want %q", tc.severity, got, tc.level)
		}
	}
}

// TestSARIFCarriesARTEXSpecificFieldsAsProperties ensures the fields no
// generic SARIF viewer understands (POE level, verification status) are not
// silently dropped on export.
func TestSARIFCarriesARTEXSpecificFieldsAsProperties(t *testing.T) {
	f := sarifFinding(7, "IDOR", "high")
	f.PoELevel = 3
	f.VerificationStatus = "verified"
	f.VerificationNote = "replayed the request with a second account"
	f.Counterevidence = "rate limiting did not block the replay"

	var out sarifLog
	if err := json.Unmarshal(FindingsSARIF([]*db.DBFinding{f}), &out); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	props := out.Runs[0].Results[0].Properties
	if props["poeLevel"].(float64) != 3 {
		t.Errorf("poeLevel lost: %v", props["poeLevel"])
	}
	if props["verification"] != "verified" {
		t.Errorf("verification status lost: %v", props["verification"])
	}
	if props["verificationNote"] != "replayed the request with a second account" {
		t.Errorf("verification note lost: %v", props["verificationNote"])
	}
	if props["counterevidence"] != "rate limiting did not block the replay" {
		t.Errorf("counterevidence lost: %v", props["counterevidence"])
	}
}

// TestSARIFRuleIDIsStableAndSafe guards the id-derivation helper: it must
// never produce an empty id (SARIF requires a non-empty rule id) and must
// normalize distinct free-text spellings of "the same" class consistently
// enough that case/whitespace differences do not fork one vulnerability class
// into two rules.
func TestSARIFRuleIDIsStableAndSafe(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SQL Injection", "sql-injection"},
		{"  SQL   Injection  ", "sql-injection"},
		{"sql injection", "sql-injection"},
		{"", "uncategorized"},
		{"   ", "uncategorized"},
		{"XSS (reflected)", "xss-reflected"},
	}
	for _, tc := range cases {
		if got := sarifRuleID(tc.in); got != tc.want {
			t.Errorf("sarifRuleID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
