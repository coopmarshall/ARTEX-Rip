package traffic

import (
	"io"
	"strings"
	"testing"
)

// TestSplitLegacyEvidenceSplitsOnBlankLine covers the header/body separator
// detection splitLegacyEvidence exists for, for both line-ending conventions
// a legacy-stored request/response blob might use.
func TestSplitLegacyEvidenceSplitsOnBlankLine(t *testing.T) {
	cases := []struct {
		name, in, wantHead, wantBody string
	}{
		{"LF", "Host: a\nAccept: b\n\nbody bytes here", "Host: a\nAccept: b\n", "body bytes here"},
		{"CRLF", "Host: a\r\nAccept: b\r\n\r\nbody bytes here", "Host: a\r\nAccept: b\r\n", "body bytes here"},
		{"empty body after separator", "Host: a\n\n", "Host: a\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			head, body, err := splitLegacyEvidence(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if head != tc.wantHead {
				t.Fatalf("head = %q, want %q", head, tc.wantHead)
			}
			rest, err := io.ReadAll(body)
			if err != nil {
				t.Fatalf("reading remaining body: %v", err)
			}
			if string(rest) != tc.wantBody {
				t.Fatalf("body = %q, want %q", rest, tc.wantBody)
			}
		})
	}
}

// TestSplitLegacyEvidenceNoSeparatorConsumesEverythingAsHead covers the
// fallback when a legacy blob has no blank-line separator at all: everything
// read becomes the head and the remaining reader is empty, rather than
// erroring or hanging.
func TestSplitLegacyEvidenceNoSeparatorConsumesEverythingAsHead(t *testing.T) {
	in := "just a single line with no separator, no trailing newline"
	head, body, err := splitLegacyEvidence(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if head != in {
		t.Fatalf("head = %q, want the entire input %q", head, in)
	}
	rest, err := io.ReadAll(body)
	if err != nil || len(rest) != 0 {
		t.Fatalf("expected an empty remaining body, got %q (err=%v)", rest, err)
	}
}

// TestSplitLegacyEvidenceRejectsOversizedHeader covers the 1MB header cap:
// a legacy blob with no separator for over a megabyte must error rather than
// buffer unbounded memory.
func TestSplitLegacyEvidenceRejectsOversizedHeader(t *testing.T) {
	huge := strings.NewReader(strings.Repeat("a", (1<<20)+100) + "\n")
	_, _, err := splitLegacyEvidence(huge)
	if err == nil {
		t.Fatal("expected an error for an oversized header with no separator")
	}
}
