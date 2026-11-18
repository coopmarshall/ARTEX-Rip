package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// pagerDutyEndpoint is PagerDuty's Events API v2 "enqueue" endpoint. Unlike
// every other channel, the destination is not configurable: PagerDuty routes
// purely on the routing_key in the request body, so there is no user-supplied
// URL and therefore no SSRF surface to validate for this channel.
//
// A var, not a const, solely so tests can point it at an httptest server —
// every other channel gets that for free from its cfg["webhook"/"url"], but
// this one has no per-config URL to redirect.
var pagerDutyEndpoint = "https://events.pagerduty.com/v2/enqueue"

// pagerDutySummaryLimit is PagerDuty's documented maximum for payload.summary
// (characters); longer values are truncated by the API itself, but truncating
// client-side keeps the delivery history's rendering of what was actually
// sent accurate.
const pagerDutySummaryLimit = 1024

// pagerDutyClosedStatuses are the finding statuses that should resolve an
// open PagerDuty incident instead of triggering a new one. A status change
// into one of these is the one place in this package where a notification
// event maps onto an incident **lifecycle** transition rather than a message
// to render — every other channel just formats text.
var pagerDutyClosedStatuses = map[string]bool{
	"resolved": true, "fixed": true, "false_positive": true,
	"duplicate": true, "risk_accepted": true, "ignored": true,
}

// pagerDutyChannel implements the PagerDuty Events API v2 ("Events API v2
// integration" / routing key, not a webhook URL).
//
// Platform traits:
//   - The routing key is the entire credential, and it is **not** a URL — the
//     endpoint is fixed. SecretKeys/DestinationKeys both name it: changing it
//     changes where the event routes to, exactly like WeCom's/Slack's/
//     Discord's single webhook field, just carried in the body instead of
//     the URL.
//   - Success is HTTP 202 with a JSON body; failures carry a real HTTP
//     status (400 malformed event, 429 rate limited), so doJSON's existing
//     status-based classification is sufficient, same as Slack/Discord.
//   - A finding's lifecycle, not just its content, matters here: a
//     finding_status_changed event into a closed status (fixed, resolved,
//     false_positive, duplicate, risk_accepted, ignored) sends
//     event_action=resolve with the same dedup_key as the original trigger,
//     so the on-call incident actually closes instead of staying open
//     forever. Every other event sends event_action=trigger.
//   - A digest batch cannot be split into N PagerDuty events without
//     breaking the "one message, one HTTP request" invariant the rate
//     limiter depends on (see server/notifier.go), so a digest becomes one
//     incident summarizing the whole batch, with no dedup_key (each digest
//     is its own incident; there is no single finding to resolve later).
type pagerDutyChannel struct{}

func (pagerDutyChannel) Kind() string { return KindPagerDuty }

// PagerDuty's Events API v2 allows roughly 2 requests/second per routing key
// (120/min); 60/min is the conservative sustained rate.
func (pagerDutyChannel) DefaultRatePerMin() int { return 60 }

func (pagerDutyChannel) SecretKeys() []string { return []string{"routing_key"} }

func (pagerDutyChannel) DestinationKeys() []string { return []string{"routing_key"} }

func (pagerDutyChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "routing_key") == "" {
		return errors.New("missing Routing Key")
	}
	return nil
}

func (c pagerDutyChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	payload, dedupKey, action, kept := pagerDutyEvent(m)
	if kept == 0 {
		return 0, nil
	}
	body := map[string]any{
		"routing_key":  cfgString(cfg, "routing_key"),
		"event_action": action,
		"client":       "ARTEX",
		"payload":      payload,
	}
	if dedupKey != "" {
		body["dedup_key"] = dedupKey
	}
	if m.HomeURL != "" {
		body["client_url"] = m.HomeURL
	}
	if _, err := doJSON(ctx, "POST", pagerDutyEndpoint, nil, body); err != nil {
		return 0, err
	}
	return kept, nil
}

// pagerDutySeverity maps ARTEX severity to a PagerDuty Events API v2 payload
// severity (one of critical/error/warning/info). Unlike SeverityRank (where
// an unknown severity must rank lowest so it never clears a notification
// threshold), an unrecognized value here still needs one of the four
// allowed enum values, so it defaults to the least alarming, "info".
func pagerDutySeverity(severity string) string {
	switch severity {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

// pagerDutyDedupKey derives PagerDuty's dedup_key from a finding id, so a
// later resolve for the same finding targets the incident its trigger opened
// instead of PagerDuty treating it as unrelated.
func pagerDutyDedupKey(findingID int64) string {
	return fmt.Sprintf("artex-finding-%d", findingID)
}

// pagerDutyEvent builds the payload, dedup_key, and event_action for one
// Send call, and returns kept (see Channel.Send) as its last value.
func pagerDutyEvent(m Message) (payload map[string]any, dedupKey, action string, kept int) {
	lim := m.limits()
	if m.Batch {
		if len(m.Items) == 0 {
			return nil, "", "", 0
		}
		counts := map[string]int{}
		for _, it := range m.Items {
			counts[it.Severity]++
		}
		worst := "info"
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if counts[sev] > 0 {
				worst = pagerDutySeverity(sev)
				break
			}
		}
		var lines []string
		for i, it := range m.Items {
			if i >= 10 { // keep custom_details readable; the dashboard has the rest
				lines = append(lines, fmt.Sprintf("… and %d more", len(m.Items)-i))
				break
			}
			lines = append(lines, fmt.Sprintf("%s · %s", SeverityLabel(it.Severity), it.Title()))
		}
		summary := fmt.Sprintf("%d new vulnerabilities", len(m.Items))
		if m.WindowMinutes > 0 {
			summary = fmt.Sprintf("%s in the last %d min", summary, m.WindowMinutes)
		}
		return map[string]any{
			"summary":        TruncateRunes(summary, pagerDutySummaryLimit),
			"source":         "ARTEX",
			"severity":       worst,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
			"custom_details": map[string]any{"items": lines, "total": len(m.Items)},
		}, "", "trigger", len(m.Items)
	}

	if len(m.Items) == 0 {
		return nil, "", "", 0
	}
	it := m.Items[0]
	action = "trigger"
	if it.IsStatusChange() && pagerDutyClosedStatuses[it.ToStatus] {
		action = "resolve"
	}
	summary := fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), it.Title())
	if it.IsStatusChange() {
		summary = fmt.Sprintf("%s (%s → %s)", summary, StatusLabel(it.FromStatus), StatusLabel(it.ToStatus))
	} else if s := OneLine(it.Summary, lim.SummaryRunes); s != "" {
		summary = summary + ": " + s
	}
	details := map[string]any{"finding_id": it.FindingID, "status": it.ToStatus}
	if it.VulnClass != "" {
		details["class"] = it.VulnClass
	}
	if a := assetLine(it.Assets, lim.AssetsShown); a != "" {
		details["assets"] = a
	}
	payload = map[string]any{
		"summary":        TruncateRunes(strings.TrimSpace(summary), pagerDutySummaryLimit),
		"source":         "ARTEX",
		"severity":       pagerDutySeverity(it.Severity),
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"custom_details": details,
	}
	return payload, pagerDutyDedupKey(it.FindingID), action, 1
}
