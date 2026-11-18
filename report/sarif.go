package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// SARIF (Static Analysis Results Interchange Format, OASIS 2.1.0) export for
// the findings page, so a vulnerability batch can be ingested directly by
// code-scanning dashboards (GitHub Code Scanning, GitLab, most SAST/DAST
// aggregators) that already know how to display a .sarif file, instead of
// needing a bespoke parser for ARTEX's own JSON shape.
//
// This is a results-only export: ARTEX findings are not tied to a file/line
// (they are network/application-layer, not static-analysis hits), so
// `result.locations` is omitted — SARIF 2.1.0 makes it optional for exactly
// this reason. Everything ARTEX-specific that a generic SARIF viewer would
// not know how to render (POE level, verification status, counterevidence)
// still rides along in `result.properties`, which every conformant consumer
// must preserve even when it does not understand the keys.

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifResult struct {
	RuleID     string         `json:"ruleId"`
	RuleIndex  int            `json:"ruleIndex"`
	Level      string         `json:"level"`
	Message    sarifText      `json:"message"`
	Properties map[string]any `json:"properties,omitempty"`
}

// sarifRuleIDChars keeps rule ids readable and stable across exports: SARIF
// does not constrain the charset, but viewers group/link results by ruleId,
// so the same vulnerability class must always normalize to the same id.
var sarifRuleIDChars = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// sarifRuleID derives a stable rule id from a vulnerability class. Unlike
// FindingFilename (which must be unique per finding), several findings sharing
// one VulnClass must collapse onto the **same** rule — that is the whole
// point of SARIF's rule/result split: one rule, many results.
func sarifRuleID(vulnClass string) string {
	id := strings.ToLower(strings.TrimSpace(vulnClass))
	if id == "" {
		return "uncategorized"
	}
	id = sarifRuleIDChars.ReplaceAllString(id, "-")
	id = strings.Trim(id, "-")
	if id == "" {
		return "uncategorized"
	}
	return id
}

// sarifLevel maps ARTEX severity to a SARIF result level. Unlike
// notify.SeverityRank (where an unknown severity must rank lowest so it never
// clears a notification threshold), an unrecognized severity here still
// needs *some* level for the result to render, so it defaults to "warning"
// rather than being dropped or treated as least severe.
func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// FindingsSARIF renders a batch of findings as a SARIF 2.1.0 log.
func FindingsSARIF(fs []*db.DBFinding) []byte {
	items := append([]*db.DBFinding(nil), fs...)
	sortFindingsForExport(items)

	ruleIndex := map[string]int{}
	var rules []sarifRule
	ruleFor := func(vulnClass string) (string, int) {
		id := sarifRuleID(vulnClass)
		if idx, ok := ruleIndex[id]; ok {
			return id, idx
		}
		idx := len(rules)
		ruleIndex[id] = idx
		rules = append(rules, sarifRule{
			ID:               id,
			ShortDescription: sarifText{Text: nz(vulnClass, "Uncategorized")},
		})
		return id, idx
	}

	results := make([]sarifResult, 0, len(items))
	for _, f := range items {
		ruleID, idx := ruleFor(f.VulnClass)
		msg := findingTitle(f)
		if s := strings.TrimSpace(f.Summary); s != "" {
			msg = fmt.Sprintf("%s: %s", msg, s)
		}
		props := map[string]any{
			"findingId":  f.ID,
			"severity":   nz(f.Severity, "info"),
			"status":     nz(f.Status, "pending"),
			"foundAt":    f.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			"poeLevel":   f.PoELevel,
			"verification": nz(f.VerificationStatus, "not_assessed"),
		}
		if note := strings.TrimSpace(f.VerificationNote); note != "" {
			props["verificationNote"] = note
		}
		if ce := strings.TrimSpace(f.Counterevidence); ce != "" {
			props["counterevidence"] = ce
		}
		if cr := strings.TrimSpace(f.ConfidenceRationale); cr != "" {
			props["confidenceRationale"] = cr
		}
		if task := strings.TrimSpace(f.TaskDescription); task != "" {
			props["task"] = task
		}
		results = append(results, sarifResult{
			RuleID:     ruleID,
			RuleIndex:  idx,
			Level:      sarifLevel(f.Severity),
			Message:    sarifText{Text: msg},
			Properties: props,
		})
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	// Rule reordering above must not desync result.ruleIndex; rebuild the
	// index map against the now-sorted slice and patch every result.
	reindex := map[string]int{}
	for i, r := range rules {
		reindex[r.ID] = i
	}
	for i := range results {
		results[i].RuleIndex = reindex[results[i].RuleID]
	}

	out := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "ARTEX", Rules: rules}},
			Results: results,
		}},
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		// MarshalIndent on these fixed, JSON-safe struct types cannot fail in
		// practice (no channels/funcs/cyclic values); a nil-safe empty log is
		// a saner fallback than panicking an HTTP export handler.
		return []byte(`{"$schema":"` + sarifSchema + `","version":"` + sarifVersion + `","runs":[]}`)
	}
	return raw
}
