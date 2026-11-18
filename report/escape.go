package report

import "strings"

// mdEscapeText escapes Markdown structural metacharacters in untrusted plain-
// text content (finding titles, classes, summaries, verification notes)
// before it is interpolated into a Markdown export.
//
// Why this is mandatory: finding names, classes, and summaries come from the
// model's own report_finding call, synthesized from what the scanned target
// returned — fully untrusted, the same provenance the notify package's own
// markdownEscape guards against for the IM channels (see its doc comment).
// Without escaping, a vulnerability reported as
//
//	SQL injection on login page\n[URGENT: verify your account](http://attacker.tld)
//
// renders in any Markdown-aware viewer the export is later opened in (GitHub,
// VS Code preview, Obsidian, a pasted chat message) as a clickable external
// link, and `![](http://attacker.tld/beacon)` is fetched at render time,
// reporting "this export was opened" and leaking the viewer's IP — the exact
// risk the IM channels were hardened against, just reached through a
// downloaded file instead of a live push.
//
// This is deliberately applied only to short plain-text fields (title,
// class, summary, verification note/counterevidence/rationale), never to
// DBFinding.Report: that field is the agent's own authored Markdown report
// and escaping it would turn its intended headings/emphasis/links into
// visible backslash-litter instead of rendering — the same split FindingsMarkdown
// already draws between "Summary" (plain text) and "Detailed report"
// (written-as-Markdown).
//
// `\` is escaped first so the backslashes just added are not re-escaped.
func mdEscapeText(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// mdCodeFence returns an opening/closing fence of backticks guaranteed not to
// be closed early by a run of backticks already inside body (CommonMark: a
// fence is only closed by a run of backticks at least as long as the one
// that opened it). Untrusted evidence/PoC text can legitimately contain
// "```" — a captured response body that itself happens to contain Markdown,
// for instance — and a fixed 3-backtick fence would let that close the block
// early, dumping the remainder of the evidence as unescaped, unfenced
// Markdown instead of the literal text it is supposed to be.
func mdCodeFence(body string) string {
	longest, run := 0, 0
	for _, r := range body {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}
