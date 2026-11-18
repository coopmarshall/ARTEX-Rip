package report

import (
	"strings"
	"testing"
)

func TestMdEscapeTextNeutralizesLinkAndImageInjection(t *testing.T) {
	// The exact attack mdEscapeText exists to stop: untrusted finding content
	// forging a clickable external link or an auto-fetched tracking image in
	// whatever Markdown viewer the exported file is later opened in.
	in := "SQL injection on login page\n[URGENT: verify your account](http://attacker.tld)"
	got := mdEscapeText(in)
	if strings.Contains(got, "](http://attacker.tld)") && !strings.Contains(got, `\]\(http`) {
		// Specifically: the bracket/paren pair that makes it a clickable
		// link must not survive unescaped.
		t.Fatalf("link syntax not neutralized: %q", got)
	}
	if !strings.Contains(got, `\[URGENT`) || !strings.Contains(got, `\]\(http://attacker.tld\)`) {
		t.Fatalf("expected [ ] ( ) all escaped, got %q", got)
	}

	beacon := mdEscapeText("![](http://attacker.tld/beacon.png)")
	if strings.Contains(beacon, "![](") {
		t.Fatalf("image/beacon syntax not neutralized: %q", beacon)
	}
	if !strings.HasPrefix(beacon, `\!\[\]\(`) {
		t.Fatalf("expected ! [ ] ( all escaped, got %q", beacon)
	}
}

func TestMdEscapeTextHandlesBackslashFirst(t *testing.T) {
	// If the backslashes mdEscapeText itself inserts were later re-escaped,
	// a single input char could balloon or, worse, an already-escaped
	// sequence could decode back into live syntax depending on the reader.
	// `\` must be escaped before anything else is escaped.
	got := mdEscapeText(`\*not bold\*`)
	if got != `\\\*not bold\\\*` {
		t.Fatalf("backslash-first escaping wrong, got %q", got)
	}
}

func TestMdEscapeTextPreservesPlainText(t *testing.T) {
	// The common case must not get visual litter: an ordinary title with no
	// Markdown metacharacters should pass through unchanged.
	plain := "Reflected XSS in search parameter"
	if got := mdEscapeText(plain); got != plain {
		t.Fatalf("plain text should be unchanged, got %q", got)
	}
}

func TestMdCodeFenceClosesEarlyWithoutEnoughBackticks(t *testing.T) {
	// The bug this guards against: a fixed 3-backtick fence closes early the
	// moment untrusted content contains its own "```", dumping the remainder
	// as unescaped, unfenced Markdown.
	body := "normal line\n```\nrm -rf /\n```\nmore untrusted content here"
	fence := mdCodeFence(body)
	if len(fence) < 4 {
		t.Fatalf("fence must be longer than the longest run inside body (3), got %q", fence)
	}
	rendered := fence + "\n" + body + "\n" + fence
	// Reconstruct what a Markdown parser sees: find the first line that is
	// entirely backticks of length >= len(fence) — that must be the closing
	// fence we appended, not something inside body.
	lines := strings.Split(rendered, "\n")
	firstCloseIdx := -1
	for i := 1; i < len(lines); i++ { // skip the opening fence itself at index 0
		if isAllBackticks(lines[i]) && len(lines[i]) >= len(fence) {
			firstCloseIdx = i
			break
		}
	}
	if firstCloseIdx != len(lines)-1 {
		t.Fatalf("a run of backticks inside body closed the fence early at line %d (expected only the final line %d): %q", firstCloseIdx, len(lines)-1, rendered)
	}
}

func TestMdCodeFenceMinimumThreeBackticks(t *testing.T) {
	if fence := mdCodeFence("no backticks here"); fence != "```" {
		t.Errorf("content with no backticks should get the standard 3-backtick fence, got %q", fence)
	}
}

func isAllBackticks(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '`' {
			return false
		}
	}
	return true
}
