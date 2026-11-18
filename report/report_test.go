package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func findingNode(id int64, vulnclass, name, severity, summary, poc string) *db.Node {
	payload, _ := json.Marshal(map[string]any{
		"vulnclass": vulnclass,
		"name":      name,
		"severity":  severity,
		"summary":   summary,
		"evidence":  map[string]any{"poc": poc},
	})
	return &db.Node{ID: id, Kind: "finding", Payload: payload}
}

func TestParseFindingExtractsAllFields(t *testing.T) {
	n := findingNode(1, "SQLi", "Login SQL injection", "high", "the id param is unsanitized", "' OR 1=1--")
	f := parseFinding(n)
	if f.VulnClass != "SQLi" || f.Name != "Login SQL injection" || f.Severity != "high" ||
		f.Summary != "the id param is unsanitized" || f.PoC != "' OR 1=1--" {
		t.Fatalf("fields not extracted correctly: %+v", f)
	}
}

// TestParseFindingToleratesMalformedPayload covers the silently-ignored
// json.Unmarshal error in parseFinding: a node whose payload is not the
// expected shape (or not valid JSON at all) must degrade to a zero-value
// findingView rather than panicking the whole report render.
func TestParseFindingToleratesMalformedPayload(t *testing.T) {
	cases := []*db.Node{
		{ID: 1, Payload: json.RawMessage(`not json`)},
		{ID: 2, Payload: json.RawMessage(`null`)},
		{ID: 3, Payload: json.RawMessage(`{"vulnclass": 123}`)}, // wrong type for the field
		{ID: 4, Payload: nil},
	}
	for _, n := range cases {
		f := parseFinding(n) // must not panic
		if f.Name != "" || f.VulnClass != "" {
			t.Errorf("node %d: malformed payload should yield a zero-value view, got %+v", n.ID, f)
		}
	}
}

func TestMarkdownNoFindingsSaysSo(t *testing.T) {
	out := Markdown(Input{Title: "Task 1", Goal: "find bugs", GeneratedAt: time.Now()})
	if !strings.Contains(out, "No vulnerabilities confirmed this time") {
		t.Errorf("empty findings should say so explicitly:\n%s", out)
	}
	if !strings.Contains(out, "Confirmed findings: **0**") {
		t.Errorf("summary count wrong:\n%s", out)
	}
}

func TestMarkdownSortsBySeverityDescending(t *testing.T) {
	out := Markdown(Input{
		Title:       "Task 1",
		GeneratedAt: time.Now(),
		Findings: []*db.Node{
			findingNode(1, "A", "low finding", "low", "", ""),
			findingNode(2, "B", "critical finding", "critical", "", ""),
			findingNode(3, "C", "medium finding", "medium", "", ""),
		},
	})
	critIdx := strings.Index(out, "critical finding")
	medIdx := strings.Index(out, "medium finding")
	lowIdx := strings.Index(out, "low finding")
	if !(critIdx < medIdx && medIdx < lowIdx) {
		t.Fatalf("findings not sorted critical > medium > low, got order at positions %d/%d/%d:\n%s", critIdx, medIdx, lowIdx, out)
	}
}

func TestMarkdownIncludesAssetCounts(t *testing.T) {
	out := Markdown(Input{
		Title:       "Task 1",
		GeneratedAt: time.Now(),
		AssetCounts: map[string]int{"domain": 3, "ip": 1},
	})
	if !strings.Contains(out, "domain 3") || !strings.Contains(out, "ip 1") {
		t.Errorf("asset counts missing or malformed:\n%s", out)
	}
}

// TestMarkdownEscapesUntrustedFindingContent is report.go's half of the same
// Markdown-injection regression covered for the findings-export path in
// report/findings_test.go: Name/VulnClass/Summary/PoC here come from the
// same untrusted source (the model's report_finding call, shaped by the
// scanned target's responses) and findingView has no separate "authored
// Markdown" field to leave unescaped — unlike DBFinding.Report, everything
// here is plain text.
func TestMarkdownEscapesUntrustedFindingContent(t *testing.T) {
	out := Markdown(Input{
		Title:       "Task 1",
		GeneratedAt: time.Now(),
		Findings: []*db.Node{
			findingNode(1, "![beacon](http://attacker.tld/b.png)",
				"XSS\n[URGENT: verify your account](http://attacker.tld)",
				"high", "clicking *here* triggers the payload",
				"line one\n```\npayload\n```\nline two"),
		},
	})
	if strings.Contains(out, "](http://attacker.tld)") {
		t.Errorf("link injection from Name not neutralized:\n%s", out)
	}
	if strings.Contains(out, "![beacon](http://attacker.tld/b.png)") {
		t.Errorf("image/beacon injection from VulnClass not neutralized:\n%s", out)
	}
	if strings.Contains(out, "clicking *here* triggers") {
		t.Errorf("emphasis injection from Summary not neutralized:\n%s", out)
	}
	if !strings.Contains(out, "````") {
		t.Errorf("PoC code fence was not widened past its embedded ``` run:\n%s", out)
	}
}
