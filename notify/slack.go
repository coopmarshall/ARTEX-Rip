package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// slackTextLimit is Slack's documented maximum for a message's top-level text
// field (in characters). Payloads built with "blocks" are capped at 3000
// characters per block instead, but this channel renders a single mrkdwn text
// field, so the whole-message limit applies.
const slackTextLimit = 40000

// slackChannel implements a Slack Incoming Webhook.
//
// Platform traits:
//   - Authentication lives entirely in the URL (https://hooks.slack.com/services/T.../B.../xxx);
//     no signing needed, same shape as WeCom — the whole address is the credential.
//   - Unlike DingTalk/WeCom/Telegram, Slack reports delivery failures with a real
//     HTTP status code (400/403/404/410/500, …) instead of hiding them inside a
//     200 response, so doJSON's existing status-based retry/permanent
//     classification is sufficient without a business-errcode check.
//   - Formatting is Slack "mrkdwn", not CommonMark: *bold*, _italic_, and links
//     are `<url|text>`. Only `<url|text>` can turn arbitrary text into a
//     clickable external link, and that requires a literal unescaped `<`.
type slackChannel struct{}

func (slackChannel) Kind() string { return KindSlack }

// Slack asks integrations to stay within about one message per second per
// webhook; 60/min is the conservative sustained rate.
func (slackChannel) DefaultRatePerMin() int { return 60 }

// The Webhook URL is the entire credential, as with WeCom: anyone with the
// address can post, and there is no separate signing secret to mask.
func (slackChannel) SecretKeys() []string { return []string{"webhook"} }

func (slackChannel) DestinationKeys() []string { return []string{"webhook"} }

func (slackChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("missing Webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid Webhook URL: %w", err)
	}
	return nil
}

func (c slackChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	text, kept := slackMrkdwn(m)
	payload := map[string]any{"text": text}
	if _, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload); err != nil {
		return 0, err
	}
	return kept, nil
}

// slackMrkdwn renders the message body and returns it together with the
// number of items actually written (see Channel.Send).
func slackMrkdwn(m Message) (string, int) {
	lim := m.limits()
	if m.Batch {
		footer := ""
		if link := slackEscapeURL(m.HomeURL); link != "" {
			footer = fmt.Sprintf("\n\n<%s|View all on the platform>", link)
		}
		kept := packItemCount(m.Items, slackTextLimit, slackReservedRunes, footer, runeSize, func(it Item, idx int) string {
			return slackBatchLine(it, idx+1, lim)
		})
		items := m.Items[:kept]
		var b strings.Builder
		b.WriteString("*" + slackEscape(slackBatchTitle(m, items, len(m.Items))) + "*")
		for i, it := range items {
			b.WriteString("\n" + slackEscape(slackBatchLine(it, i+1, lim)))
		}
		b.WriteString(footer)
		return TruncateRunes(b.String(), slackTextLimit), kept
	}

	var b strings.Builder
	b.WriteString("*" + slackEscape(markdownTitle(m)) + "*")
	if len(m.Items) == 0 {
		return b.String(), 0
	}
	it := m.Items[0]
	if it.IsStatusChange() {
		fmt.Fprintf(&b, "\n*Status change*: %s → %s",
			slackEscape(StatusLabel(it.FromStatus)), slackEscape(StatusLabel(it.ToStatus)))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		b.WriteString("\n*Type*: " + slackEscape(it.VulnClass))
	}
	if a := assetLine(it.Assets, lim.AssetsShown); a != "" {
		b.WriteString("\n*Assets*: " + slackEscape(a))
	}
	if s := OneLine(it.Summary, lim.SummaryRunes); s != "" {
		b.WriteString("\n*Summary*: " + slackEscape(s))
	}
	if link := slackEscapeURL(it.DetailURL); link != "" {
		fmt.Fprintf(&b, "\n\n<%s|View details>", link)
	}
	return TruncateRunes(b.String(), slackTextLimit), 1
}

// slackReservedRunes is reserved for the message title and footer link.
const slackReservedRunes = 160

// slackBatchLine renders one entry of a digest (unescaped; the caller escapes
// it uniformly, same split as telegramBatchLine).
func slackBatchLine(it Item, idx int, lim Limits) string {
	if a := assetLine(it.Assets, lim.AssetsShown); a != "" {
		return fmt.Sprintf("%d. %s · %s — %s", idx, SeverityLabel(it.Severity), it.Title(), a)
	}
	return fmt.Sprintf("%d. %s · %s", idx, SeverityLabel(it.Severity), it.Title())
}

// slackBatchTitle renders the title line of a digest message. The count is the
// number of items **actually included in this message**, not the batch total.
func slackBatchTitle(m Message, items []Item, total int) string {
	title := fmt.Sprintf("Vulnerability digest · %d total", total)
	if extra := total - len(items); extra > 0 {
		title += fmt.Sprintf(" (showing the first %d, %d more in the next message)", len(items), extra)
	}
	if m.WindowMinutes > 0 {
		title = fmt.Sprintf("Last %d min · %s", m.WindowMinutes, title)
	}
	return title
}

// slackEscape escapes Slack mrkdwn's three reserved characters.
//
// Finding titles, summaries, and asset names come from untrusted sources (model
// output, target responses), and Slack's only way to turn text into a clickable
// link is `<url|text>` — which requires a literal `<`. Escaping `<` to `&lt;`
// neutralizes that injection outright, the same reasoning as telegramEscape;
// `&` must be escaped first so the entities just introduced are not themselves
// re-escaped.
func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// slackEscapeURL escapes a URL for use inside a Slack link token (<url|text>).
// A literal `|` or `>` in the address would end the token early or merge with
// the display text; both are rejected outright instead of partially encoded,
// since a mangled link is worse than a missing one and these characters never
// occur in a well-formed detail-page URL.
func slackEscapeURL(u string) string {
	if strings.ContainsAny(u, "|>") {
		return ""
	}
	return slackEscape(u)
}
