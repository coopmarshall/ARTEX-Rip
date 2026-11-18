package db

import (
	"strings"
	"testing"
)

// TestValidateDSLAcceptsWellFormedExpressions is a broad smoke test: this
// parser (asset_dsl.go) had no dedicated test file at all before this one,
// despite building a raw SQL WHERE clause from a user/agent-supplied query
// string.
func TestValidateDSLAcceptsWellFormedExpressions(t *testing.T) {
	ok := []string{
		"", "   ",
		"example.com",
		`domain=example.com`,
		`domain==example.com AND port>8080`,
		`(domain=a OR domain=b) AND port>=443`,
		`title!="old title"`,
		`tech==nginx`,
		`task_id=42`,
		`company_id=1`,
		`status_code<500`,
		`a and b or c`, // lowercase keywords
	}
	for _, dsl := range ok {
		if err := ValidateDSL(dsl); err != nil {
			t.Errorf("ValidateDSL(%q) = %v, want nil", dsl, err)
		}
	}
}

func TestValidateDSLRejectsMalformedExpressions(t *testing.T) {
	bad := []string{
		"(",
		"domain=a AND",
		"domain=a OR",
		"domain=a))",
		"port>notanumber",
		"task_id=notanumber",
		"company_id=notanumber",
		"port<==5", // not a real operator
	}
	for _, dsl := range bad {
		if err := ValidateDSL(dsl); err == nil {
			t.Errorf("ValidateDSL(%q) = nil, want a syntax/type error", dsl)
		}
	}
}

// TestParseDSLOperatorPrecedence locks in the documented grammar (AND binds
// tighter than OR): "a AND b OR c" must parse as "(a AND b) OR c", not
// left-to-right or OR-first.
func TestParseDSLOperatorPrecedence(t *testing.T) {
	node, err := ParseDSL("a AND b OR c")
	if err != nil {
		t.Fatal(err)
	}
	if node.kind != "or" || len(node.children) != 2 {
		t.Fatalf("top-level node = %+v, want an OR of 2 children", node)
	}
	if node.children[0].kind != "and" {
		t.Fatalf("left child = %+v, want an AND group (a AND b)", node.children[0])
	}
	if node.children[1].kind != "leaf" || node.children[1].expr.Value != "c" {
		t.Fatalf("right child = %+v, want the bare leaf c", node.children[1])
	}
}

// TestParseDSLQuotedKeywordIsLiteralText is a real bug this test file
// caught: a quoted token's content was checked against AND/OR case-
// insensitively the same as an unquoted bare word, so a user quoting "and"
// or "or" specifically to search for that literal word (e.g. a page titled
// "Terms and Conditions" searched as `"and"`) got it silently reinterpreted
// as the logical operator instead of a text search term. Quoting must be
// able to escape keyword interpretation.
func TestParseDSLQuotedKeywordIsLiteralText(t *testing.T) {
	for _, kw := range []string{`"and"`, `"AND"`, `"or"`, `"Or"`} {
		node, err := ParseDSL(kw)
		if err != nil {
			t.Fatalf("ParseDSL(%s): %v", kw, err)
		}
		if node == nil || node.kind != "leaf" {
			t.Fatalf("ParseDSL(%s) = %+v, want a single literal leaf, not an operator", kw, node)
		}
		want := strings.Trim(kw, `"`)
		if node.expr.Value != want {
			t.Fatalf("ParseDSL(%s): leaf value = %q, want %q", kw, node.expr.Value, want)
		}
	}
	// Sanity check the unquoted form still behaves as the operator, so the
	// fix is actually about quoting, not about disabling AND/OR altogether.
	node, err := ParseDSL("a and b")
	if err != nil {
		t.Fatal(err)
	}
	if node.kind != "and" {
		t.Fatalf("unquoted 'and' should still parse as the operator, got %+v", node)
	}
}

// TestParseDSLUnknownFieldFallsBackToBareText covers tryParseFieldExpr's
// rejection path: an identifier=value shape where the field name is not in
// any known-field map must not error, it degrades to a bare-text search
// over the literal string (e.g. searching for "version=2" as text).
func TestParseDSLUnknownFieldFallsBackToBareText(t *testing.T) {
	node, err := ParseDSL("notarealfield=value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.kind != "leaf" || node.expr.Field != "" || node.expr.Value != "notarealfield=value" {
		t.Fatalf("got %+v, want a single bare-text leaf for the whole literal token", node)
	}
}
