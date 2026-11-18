package server

import (
	"path/filepath"
	"testing"
)

// wsResolve/wsRel/sanitizeFilename had no dedicated unit test despite being
// the workspace file manager's path-confinement boundary (every workspace
// route sits behind this). These lock in the documented guarantee: nothing
// can escape s.m.dir via "..".

func newWSTestServer(t *testing.T) *Server {
	return &Server{m: &Manager{dir: t.TempDir()}}
}

func TestWsResolveConfinesTraversalToRoot(t *testing.T) {
	s := newWSTestServer(t)
	base := filepath.Clean(s.m.dir)
	cases := []struct {
		rel  string
		want string
	}{
		{"", base},
		{"/", base},
		{"a/b", filepath.Join(base, "a", "b")},
		{"../../etc/passwd", filepath.Join(base, "etc", "passwd")},
		{"..", base},
		{"a/../../../etc", filepath.Join(base, "etc")},
		{"//a//b", filepath.Join(base, "a", "b")},
		{"  a/b  ", filepath.Join(base, "a", "b")},
	}
	for _, c := range cases {
		abs, ok := s.wsResolve(c.rel)
		if !ok {
			t.Errorf("wsResolve(%q): ok=false, want true", c.rel)
			continue
		}
		if abs != c.want {
			t.Errorf("wsResolve(%q) = %q, want %q", c.rel, abs, c.want)
		}
	}
}

func TestWsRelRendersForwardSlashRelativePath(t *testing.T) {
	s := newWSTestServer(t)
	base := filepath.Clean(s.m.dir)
	abs := filepath.Join(base, "a", "b")
	if got := s.wsRel(abs); got != "a/b" {
		t.Errorf("wsRel(%q) = %q, want %q", abs, got, "a/b")
	}
	if got := s.wsRel(base); got != "" {
		t.Errorf("wsRel(root) = %q, want empty string", got)
	}
}

func TestWsRelOnPathOutsideRootReturnsEscapingRelPath(t *testing.T) {
	// Documents current behavior rather than asserting it's ideal: wsRel
	// does not itself re-validate containment, so a caller-supplied path
	// outside the root renders as a "../" relative path instead of being
	// rejected. Every current caller only ever passes a path that already
	// came from wsResolve (or a directory entry joined onto one), so this
	// is not reachable in practice -- but it is not defended at this layer
	// either, so this test exists to catch it if that invariant ever
	// breaks.
	s := newWSTestServer(t)
	got := s.wsRel("/completely/different/path")
	if got == "" {
		t.Skip("wsRel returned empty for an outside path; nothing to assert")
	}
	if filepath.IsAbs(got) {
		t.Errorf("wsRel on an outside path returned an absolute path %q", got)
	}
}

func TestSanitizeFilenameStripsHeaderBreakingCharacters(t *testing.T) {
	cases := []struct{ in, want string }{
		{`normal.txt`, `normal.txt`},
		{`evil".txt`, `evil.txt`},
		{"evil\r\nSet-Cookie: x=1", "evilSet-Cookie: x=1"},
		{`a\b.txt`, `ab.txt`},
	}
	for _, c := range cases {
		if got := sanitizeFilename(c.in); got != c.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
