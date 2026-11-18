package mcphttp

import (
	"strings"
	"testing"
)

// parseSSE had no dedicated unit test (0% coverage) despite being a pure
// parser over an io.Reader (the legacy SSE transport's response decoder).
// These lock in its documented behavior: skip server-to-client
// requests/notifications, tolerate a missing trailing blank line, and
// ignore malformed/non-matching frames rather than erroring on them.

func TestParseSSEReturnsMatchingResponse(t *testing.T) {
	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
	resp, err := parseSSE(strings.NewReader(stream), 1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != 1 {
		t.Fatalf("resp.ID = %d, want 1", resp.ID)
	}
}

func TestParseSSESkipsNotificationsAndServerRequestsBeforeMatch(t *testing.T) {
	stream := "" +
		"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
	resp, err := parseSSE(strings.NewReader(stream), 1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != 1 {
		t.Fatalf("resp.ID = %d, want 1", resp.ID)
	}
}

func TestParseSSEIgnoresMalformedFrames(t *testing.T) {
	stream := "data: not json at all\n\n" + "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	resp, err := parseSSE(strings.NewReader(stream), 1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != 1 {
		t.Fatalf("resp.ID = %d, want 1", resp.ID)
	}
}

func TestParseSSEWorksWithoutTrailingBlankLine(t *testing.T) {
	stream := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"
	resp, err := parseSSE(strings.NewReader(stream), 1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != 1 {
		t.Fatalf("resp.ID = %d, want 1", resp.ID)
	}
}

func TestParseSSEIgnoresOtherFieldsAndComments(t *testing.T) {
	stream := ": keep-alive comment\nid: 7\nevent: message\nretry: 3000\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	resp, err := parseSSE(strings.NewReader(stream), 1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != 1 {
		t.Fatalf("resp.ID = %d, want 1", resp.ID)
	}
}

func TestParseSSEErrorsWhenNoMatchFound(t *testing.T) {
	stream := "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n"
	_, err := parseSSE(strings.NewReader(stream), 1)
	if err == nil {
		t.Fatal("expected an error when the stream never contains a matching id")
	}
}

func TestParseSSEHandlesCRLFLineEndings(t *testing.T) {
	stream := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n"
	resp, err := parseSSE(strings.NewReader(stream), 1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != 1 {
		t.Fatalf("resp.ID = %d, want 1", resp.ID)
	}
}
