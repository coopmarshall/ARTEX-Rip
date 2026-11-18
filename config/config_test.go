package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostgresDSNPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","port":6000,"user":"u","password":"p","dbname":"d","sslmode":"require"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)

	// no env DSN → built from config file fields
	t.Setenv("ARTEX_PG_DSN", "")
	got, _, err := PostgresDSN()
	want := "postgres://u:p@10.1.2.3:6000/d?sslmode=require"
	if err != nil || got != want {
		t.Fatalf("from file: got %q err %v want %q", got, err, want)
	}

	// env wins over config file
	t.Setenv("ARTEX_PG_DSN", "postgres://envwins/x")
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://envwins/x" {
		t.Fatalf("env should win, got %q err %v", got, err)
	}

	// no env, no file → error (no built-in default)
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(dir, "nope.json"))
	if got, _, err := PostgresDSN(); err == nil {
		t.Fatalf("missing config should error, got %q", got)
	}

	// full dsn in config file is used verbatim
	os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://full/dsn" {
		t.Fatalf("file dsn verbatim, got %q err %v", got, err)
	}
}

// A config file that exists but is not valid JSON must fail loudly, not run with
// defaults (or report "no database config") as if the file were absent.
func TestMalformedConfigIsAnError(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	// What install.sh used to write for a password containing a double quote.
	os.WriteFile(cfgPath, []byte(`{"database":{"host":"h","password":"a"b","dbname":"d"},"skill_dir":"/s"}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_SKILL_DIR", "")

	if _, _, err := PostgresDSN(); err == nil || !strings.Contains(err.Error(), "parse config file") {
		t.Fatalf("PostgresDSN: want a parse error, got %v", err)
	}
	if d, err := SkillDir(); err == nil {
		t.Fatalf("SkillDir: want a parse error, got dir %q", d)
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load: want a parse error")
	}
}

// TestRedactMasksPasswordInBothDSNForms is the actual security property
// Redact exists for: whatever the caller logs the result of (db.go wraps a
// failed-ping error with it) must never contain the real password.
// PostgreSQL DSNs come in two interchangeable forms — the postgres:// URL
// this package's own buildDSN always produces, and libpq's keyword/value
// syntax, which ARTEX_PG_DSN (user-supplied) may equally well use — and
// url.Parse does not error on the second form, it just parses it as an
// opaque path with no Userinfo, so the URL-only masking silently never
// fires. Confirmed by hand before fixing: the old code returned a
// keyword/value DSN with its password fully intact.
func TestRedactMasksPasswordInBothDSNForms(t *testing.T) {
	cases := []struct {
		name, dsn string
	}{
		{"URL form", "postgres://user:secretpw@host:5432/db?sslmode=disable"},
		{"keyword/value form", "host=localhost user=postgres password=secretpw dbname=mydb sslmode=disable"},
		{"keyword/value, password first", "password=secretpw host=localhost user=postgres"},
		{"keyword/value, quoted password with a space", "host=localhost password='sec ret pw' dbname=mydb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.dsn)
			if strings.Contains(got, "secretpw") || strings.Contains(got, "sec ret pw") {
				t.Fatalf("password leaked through Redact: %q", got)
			}
		})
	}
}

// TestRedactLeavesNonSensitiveInputsAlone covers the paths that must not be
// mangled: no password present, and an unparseable/non-DSN string (Redact
// must degrade gracefully, not panic or corrupt the input).
func TestRedactLeavesNonSensitiveInputsAlone(t *testing.T) {
	cases := []string{
		"postgres://user@host:5432/db", // no password at all
		"",
		"not a dsn at all, just text",
	}
	for _, dsn := range cases {
		if got := Redact(dsn); strings.Contains(got, "password=****") {
			t.Errorf("Redact(%q) = %q, should not have invented a password field", dsn, got)
		}
	}
}
