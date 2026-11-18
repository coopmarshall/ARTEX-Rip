package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// opsgenieEndpoint is Opsgenie's Alert API v2 base; like PagerDuty, the
// destination is not user-configurable (routing happens on the API key), so
// there is no SSRF surface to validate for this channel either.
//
// A var, not a const, solely so tests can point it at an httptest server —
// see pagerDutyEndpoint's doc comment for the same reasoning.
var opsgenieEndpoint = "https://api.opsgenie.com/v2/alerts"

// opsgenieMessageLimit is Opsgenie's documented hard limit for the alert
// "message" field (characters); unlike most platforms' soft truncation, the
// API rejects a longer value outright, so this must be enforced client-side.
const opsgenieMessageLimit = 130

// opsgenieDescriptionLimit is the documented limit for "description"
// (characters). Findings rarely get close to it, but it is still enforced
// defensively rather than trusting every caller's input forever.
const opsgenieDescriptionLimit = 15000

// opsgenieClosedStatuses mirrors pagerDutyClosedStatuses: the finding
// statuses that should close an open Opsgenie alert.
var opsgenieClosedStatuses = pagerDutyClosedStatuses

// opsgenieChannel implements the Opsgenie Alert API v2.
//
// Platform traits:
//   - The API key is the entire credential, sent as an Authorization:
//     GenieKey header rather than embedded in a URL or body field — the one
//     channel in this package whose credential is neither a URL nor a body
//     field read by cfgString into the payload directly.
//   - create-alert is **not naturally idempotent**: POSTing with an alias
//     that already has an *open* alert returns 409. PagerDuty's trigger
//     avoids this because its dedup_key semantics merge repeated triggers
//     into the same open incident; Opsgenie has no equivalent "merge" verb
//     on the create endpoint. To stay on the right side of that without
//     tracking alert state ourselves, this channel only ever calls
//     create-alert from a non-status-change event (a finding's first
//     notification) and routes every subsequent status change to either
//     close (terminal statuses) or add-note (everything else) — both of
//     which are safe to call repeatedly regardless of the alert's current
//     state. The one case this does not cover: if a finding_created event
//     is ever delivered twice for the same finding (e.g. a retry after a
//     response was lost after the server-side create actually succeeded),
//     the second create will 409 and that delivery will show as failed.
//   - Success is 202 Accepted with a JSON body; failures carry a real HTTP
//     status, so doJSON's existing status-based classification applies.
type opsgenieChannel struct{}

func (opsgenieChannel) Kind() string { return KindOpsgenie }

// Opsgenie's documented default rate limit is generous (100 req/sec per
// integration); 60/min is a conservative sustained rate consistent with the
// other incident-management channel (PagerDuty).
func (opsgenieChannel) DefaultRatePerMin() int { return 60 }

func (opsgenieChannel) SecretKeys() []string { return []string{"api_key"} }

func (opsgenieChannel) DestinationKeys() []string { return []string{"api_key"} }

func (opsgenieChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "api_key") == "" {
		return errors.New("missing API Key")
	}
	return nil
}

func (c opsgenieChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	method, path, payload, kept := opsgenieRequest(m)
	if kept == 0 {
		return 0, nil
	}
	headers := map[string]string{"Authorization": "GenieKey " + cfgString(cfg, "api_key")}
	if _, err := doJSON(ctx, method, opsgenieEndpoint+path, headers, payload); err != nil {
		return 0, err
	}
	return kept, nil
}

// opsgeniePriority maps ARTEX severity to an Opsgenie priority (P1 highest to
// P5 lowest). An unrecognized severity defaults to P5, the least alarming
// value — the same "do not over-alarm on the unknown case" choice as
// notify.SeverityRank and pagerDutySeverity.
func opsgeniePriority(severity string) string {
	switch severity {
	case "critical":
		return "P1"
	case "high":
		return "P2"
	case "medium":
		return "P3"
	case "low":
		return "P4"
	default:
		return "P5"
	}
}

// opsgenieWorstSeverity returns the highest-ranked severity present in items,
// defaulting to "low" when items carries only unrecognized severities (never
// an unknown/empty string, since it feeds directly into opsgeniePriority).
func opsgenieWorstSeverity(items []Item) string {
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		for _, it := range items {
			if it.Severity == sev {
				return sev
			}
		}
	}
	return "low"
}

// opsgenieRequest builds the HTTP method, path (relative to opsgenieEndpoint),
// and JSON body for one Send call, and returns kept (see Channel.Send) as its
// last value. See the opsgenieChannel doc comment for why the action
// (create/close/note) is chosen the way it is.
func opsgenieRequest(m Message) (method, path string, payload map[string]any, kept int) {
	lim := m.limits()
	if m.Batch {
		if len(m.Items) == 0 {
			return "", "", nil, 0
		}
		worst := opsgenieWorstSeverity(m.Items)
		var lines []string
		for i, it := range m.Items {
			if i >= 20 {
				lines = append(lines, fmt.Sprintf("… and %d more", len(m.Items)-i))
				break
			}
			lines = append(lines, fmt.Sprintf("%s - %s", SeverityLabel(it.Severity), it.Title()))
		}
		message := fmt.Sprintf("%d new vulnerabilities", len(m.Items))
		if m.WindowMinutes > 0 {
			message = fmt.Sprintf("%s (last %d min)", message, m.WindowMinutes)
		}
		return "POST", "", map[string]any{
			"message":     TruncateRunes(message, opsgenieMessageLimit),
			"description": TruncateRunes(strings.Join(lines, "\n"), opsgenieDescriptionLimit),
			"priority":    opsgeniePriority(worst),
		}, len(m.Items)
	}

	if len(m.Items) == 0 {
		return "", "", nil, 0
	}
	it := m.Items[0]
	alias := alertCorrelationKey(it.FindingID)
	escapedAlias := url.PathEscape(alias)

	if it.IsStatusChange() {
		if opsgenieClosedStatuses[it.ToStatus] {
			return "POST", "/" + escapedAlias + "/close?identifierType=alias",
				map[string]any{"note": fmt.Sprintf("%s → %s", StatusLabel(it.FromStatus), StatusLabel(it.ToStatus))}, 1
		}
		return "POST", "/" + escapedAlias + "/notes?identifierType=alias",
			map[string]any{"note": fmt.Sprintf("Status changed: %s → %s", StatusLabel(it.FromStatus), StatusLabel(it.ToStatus))}, 1
	}

	message := fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), it.Title())
	var details []string
	if it.VulnClass != "" {
		details = append(details, "Class: "+it.VulnClass)
	}
	if a := assetLine(it.Assets, lim.AssetsShown); a != "" {
		details = append(details, "Assets: "+a)
	}
	if s := OneLine(it.Summary, lim.SummaryRunes); s != "" {
		details = append(details, "Summary: "+s)
	}
	if it.DetailURL != "" {
		details = append(details, "Details: "+it.DetailURL)
	}
	payload = map[string]any{
		"message":  TruncateRunes(message, opsgenieMessageLimit),
		"alias":    alias,
		"priority": opsgeniePriority(it.Severity),
	}
	if len(details) > 0 {
		payload["description"] = TruncateRunes(strings.Join(details, "\n"), opsgenieDescriptionLimit)
	}
	if it.VulnClass != "" || it.Severity != "" {
		tags := make([]string, 0, 2)
		if it.Severity != "" {
			tags = append(tags, it.Severity)
		}
		if it.VulnClass != "" {
			tags = append(tags, it.VulnClass)
		}
		payload["tags"] = tags
	}
	return "POST", "", payload, 1
}
