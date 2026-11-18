package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// discordTextLimit is Discord's documented maximum for a message's content
// field, in characters.
const discordTextLimit = 2000

// discordReservedRunes is reserved for the message title and footer link.
const discordReservedRunes = 160

// discordChannel implements a Discord webhook.
//
// Platform traits:
//   - Authentication lives entirely in the URL
//     (https://discord.com/api/webhooks/<id>/<token>); the whole address is
//     the credential, same shape as WeCom/Slack.
//   - Success is a plain 2xx (204 with no body, unless ?wait=true is added,
//     which this channel does not need); failures carry a real HTTP status
//     plus a JSON {code,message} body, so doJSON's existing status-based
//     classification is sufficient, same as Slack.
//   - Discord message content supports the same CommonMark-ish markdown as
//     DingTalk/WeCom (*bold*, `code`, ~~strike~~, ||spoiler||, blockquotes),
//     so this channel reuses markdownEscape/markdownText rather than
//     inventing a fourth escaping convention. Unlike DingTalk/WeCom/Slack,
//     Discord message content does **not** render `[text](url)` or
//     `<url|text>` as a masked link — a raw URL on its own line is the only
//     way to get a clickable backlink, so DetailURL/HomeURL are emitted
//     as-is (they are admin-configured public_base_url, not untrusted
//     content, matching writeItem's convention).
//   - Untrusted content can still weaponize `@everyone`, `@here`, or a raw
//     `<@id>`/`<@&id>` mention written as literal text inside a finding
//     title pulled from a scanned target. Discord's webhook payload accepts
//     `allowed_mentions` to suppress all mention parsing server-side, which
//     is strictly more reliable than trying to escape every mention syntax
//     ourselves, so it is always sent.
type discordChannel struct{}

func (discordChannel) Kind() string { return KindDiscord }

// Discord's documented safe rate for one webhook is about 30 requests/minute
// sustained (the hard limit is a 5-per-2-seconds burst, but that burst drains
// fast under a digest workload).
func (discordChannel) DefaultRatePerMin() int { return 30 }

// The Webhook URL is the entire credential: anyone with the address can post,
// and there is no separate signing secret to mask.
func (discordChannel) SecretKeys() []string { return []string{"webhook"} }

func (discordChannel) DestinationKeys() []string { return []string{"webhook"} }

func (discordChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("missing Webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid Webhook URL: %w", err)
	}
	return nil
}

func (c discordChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	content, kept := discordMarkdown(m)
	payload := map[string]any{
		"content": content,
		// Suppress every mention type; see the type doc comment for why this
		// must be server-enforced rather than escaped client-side.
		"allowed_mentions": map[string]any{"parse": []string{}},
	}
	if _, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload); err != nil {
		return 0, err
	}
	return kept, nil
}

// discordMarkdown renders the message body and returns it together with the
// number of items actually written (see Channel.Send).
func discordMarkdown(m Message) (string, int) {
	lim := m.limits()
	if m.Batch {
		footer := ""
		if m.HomeURL != "" {
			footer = "\n\nView all on the platform: " + m.HomeURL
		}
		kept := packItemCount(m.Items, discordTextLimit, discordReservedRunes, footer, runeSize, func(it Item, idx int) string {
			return discordBatchLine(it, idx+1, lim)
		})
		items := m.Items[:kept]
		var b strings.Builder
		b.WriteString("**" + markdownEscape(discordBatchTitle(m, items, len(m.Items))) + "**")
		for i, it := range items {
			b.WriteString("\n" + markdownEscape(discordBatchLine(it, i+1, lim)))
		}
		b.WriteString(footer)
		return TruncateRunes(b.String(), discordTextLimit), kept
	}

	var b strings.Builder
	b.WriteString("**" + markdownEscape(markdownTitle(m)) + "**")
	if len(m.Items) == 0 {
		return b.String(), 0
	}
	it := m.Items[0]
	if it.IsStatusChange() {
		fmt.Fprintf(&b, "\n**Status change**: %s → %s",
			markdownEscape(StatusLabel(it.FromStatus)), markdownEscape(StatusLabel(it.ToStatus)))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		b.WriteString("\n**Type**: " + markdownEscape(it.VulnClass))
	}
	if a := assetLine(it.Assets, lim.AssetsShown); a != "" {
		b.WriteString("\n**Assets**: " + markdownEscape(a))
	}
	if s := OneLine(it.Summary, lim.SummaryRunes); s != "" {
		b.WriteString("\n**Summary**: " + markdownEscape(s))
	}
	if it.DetailURL != "" {
		b.WriteString("\n\nView details: " + it.DetailURL)
	}
	return TruncateRunes(b.String(), discordTextLimit), 1
}

// discordBatchLine renders one entry of a digest (unescaped; the caller
// escapes it uniformly, same split as telegramBatchLine/slackBatchLine).
func discordBatchLine(it Item, idx int, lim Limits) string {
	if a := assetLine(it.Assets, lim.AssetsShown); a != "" {
		return fmt.Sprintf("%d. %s · %s — %s", idx, SeverityLabel(it.Severity), it.Title(), a)
	}
	return fmt.Sprintf("%d. %s · %s", idx, SeverityLabel(it.Severity), it.Title())
}

// discordBatchTitle renders the title line of a digest message. The count is
// the number of items **actually included in this message**, not the batch
// total.
func discordBatchTitle(m Message, items []Item, total int) string {
	title := fmt.Sprintf("Vulnerability digest · %d total", total)
	if extra := total - len(items); extra > 0 {
		title += fmt.Sprintf(" (showing the first %d, %d more in the next message)", len(items), extra)
	}
	if m.WindowMinutes > 0 {
		title = fmt.Sprintf("Last %d min · %s", m.WindowMinutes, title)
	}
	return title
}
