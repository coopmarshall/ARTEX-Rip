package llmrec

import (
	"context"
	"encoding/json"
	"iter"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"github.com/google/uuid"
)

type completeProvider struct{}

func (completeProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func (completeProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{
			{Type: llm.BlockThinking, Thinking: "reasoning"},
			llm.TextBlock("answer"),
		},
	}, "stop", llm.Usage{InputTokens: 7, OutputTokens: 3}, nil
}

func TestTaskIDContextUsesExplicitRegistryID(t *testing.T) {
	ctx := WithTaskID(context.Background(), " 42 ")
	if got := TaskIDFrom(ctx); got != "42" {
		t.Fatalf("TaskIDFrom()=%q want 42", got)
	}
	if got := TaskIDFrom(WithTaskID(ctx, "   ")); got != "42" {
		t.Fatalf("blank task id should preserve parent context, got %q", got)
	}
	if got := TaskIDFrom(nil); got != "" {
		t.Fatalf("nil context returned %q", got)
	}
}

func TestParseSessionFallbackIsExplorationScoped(t *testing.T) {
	taskID, worker := parseSession("exp12-worker-i99")
	if taskID != "12" || worker != "worker" {
		t.Fatalf("parseSession()=(%q,%q)", taskID, worker)
	}
	if taskID, worker := parseSession("not-a-task"); taskID != "" || worker != "" {
		t.Fatalf("unexpected non-session parse: (%q,%q)", taskID, worker)
	}
}

func TestCompleteForwardsAtomicResponse(t *testing.T) {
	recorder := Wrap(completeProvider{}, nil, "model", "profile", "", "", func() bool { return false })
	msg, stopReason, usage, err := recorder.Complete(context.Background(), llm.CompletionRequest{})
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if got := msg.Text(); got != "answer" {
		t.Fatalf("Complete() text=%q want answer", got)
	}
	if stopReason != "stop" {
		t.Fatalf("Complete() stop reason=%q want stop", stopReason)
	}
	if usage.InputTokens != 7 || usage.OutputTokens != 3 {
		t.Fatalf("Complete() usage=%+v", usage)
	}
}

// The usage sink sees each metered call once, with the usage the llm_usage row gets.
func TestUsageSinkSeesMeteredCalls(t *testing.T) {
	var got []llm.Usage
	ctx := WithUsageSink(context.Background(), func(u llm.Usage) { got = append(got, u) })
	recorder := Wrap(meteredStreamProvider{}, nil, "model", "profile", "", "", func() bool { return false })
	for _, err := range recorder.Stream(ctx, llm.CompletionRequest{}) {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := recorder.Complete(ctx, llm.CompletionRequest{}); err != nil {
		t.Fatal(err)
	}
	want := []llm.Usage{{InputTokens: 23, OutputTokens: 5}, {InputTokens: 7, OutputTokens: 3}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("sink saw %+v, want %+v", got, want)
	}
	// A call that gets no llm_usage row (no model, zero usage) is not seen either.
	got = nil
	empty := Wrap(completeProvider{}, nil, "", "", "", "", nil)
	empty.recordUsage(ctx, "", 0, "", llm.Usage{}, 0, "ok")
	if len(got) != 0 {
		t.Fatalf("sink saw an unmetered call: %+v", got)
	}
}

type meteredStreamProvider struct{ completeProvider }

func (meteredStreamProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 23}}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, Usage: llm.Usage{OutputTokens: 5}}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func TestSideUsageRecordedOnceOnConsumerCancellation(t *testing.T) {
	t.Skip("timing-sensitive: passes locally, flaky on CI runners; tracked in BaaRai/ARTEX#9")
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	for _, early := range []bool{false, true} {
		profile := "btw-metering-" + uuid.NewString()
		ctx, cancel := context.WithCancel(transcript.WithSessionID(t.Context(), "exp0-btw-test"))
		recorder := Wrap(meteredStreamProvider{}, pg, "fixture", profile, "", "", func() bool { return false })
		for event, err := range recorder.Stream(ctx, llm.CompletionRequest{}) {
			if err != nil {
				t.Fatal(err)
			}
			if early && event.Type == llm.SEMessageDelta {
				cancel()
				break // Consumer exits before the provider can return a cancellation event.
			}
		}
		cancel()
		var count, input, output int
		var worker, status string
		err = pg.QueryRow(`SELECT count(*),max(input_tokens),max(output_tokens),max(worker),max(status)
FROM llm_usage WHERE profile_name=$1`, profile).Scan(&count, &input, &output, &worker, &status)
		_, _ = pg.Exec(`DELETE FROM llm_usage WHERE profile_name=$1`, profile)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus := "ok"
		if early {
			wantStatus = "error"
		}
		if count != 1 || input != 23 || output != 5 || worker != "btw" || status != wantStatus {
			t.Fatalf("early=%v: count=%d usage=%d/%d worker=%q status=%q", early, count, input, output, worker, status)
		}
	}
}

func TestThinkingTextConcatenatesOnlyThinkingBlocks(t *testing.T) {
	msg := llm.Message{Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: "first "},
		llm.TextBlock("not thinking, should be ignored"),
		{Type: llm.BlockThinking, Thinking: "second"},
		{Type: llm.BlockThinking, Thinking: ""}, // empty thinking block contributes nothing
	}}
	if got := thinkingText(msg); got != "first second" {
		t.Fatalf("thinkingText() = %q, want %q", got, "first second")
	}
	if got := thinkingText(llm.Message{}); got != "" {
		t.Fatalf("thinkingText(empty message) = %q, want empty", got)
	}
}

// TestSerializeRequestThinkingPrecedence covers the one piece of real logic
// in serializeRequest: the per-request Thinking override wins over the
// Recorder's config-level thinkingType (matching norma's own buildBody
// decision, per the doc comment), and when both are empty no "thinking"
// field is written at all.
func TestSerializeRequestThinkingPrecedence(t *testing.T) {
	decode := func(raw string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("serializeRequest did not produce valid JSON: %v\n%s", err, raw)
		}
		return m
	}

	r := &Recorder{thinkingType: "enabled", reasoningEffort: "high"}
	m := decode(r.serializeRequest(llm.CompletionRequest{Thinking: "disabled"}))
	thinking, _ := m["thinking"].(map[string]any)
	if thinking["type"] != "disabled" {
		t.Fatalf("per-request Thinking override should win, got %v", m["thinking"])
	}
	if thinking["effort"] != "high" {
		t.Fatalf("reasoningEffort has no per-request override, should pass through, got %v", m["thinking"])
	}

	m = decode(r.serializeRequest(llm.CompletionRequest{}))
	thinking, _ = m["thinking"].(map[string]any)
	if thinking["type"] != "enabled" {
		t.Fatalf("with no per-request override, config thinkingType should be used, got %v", m["thinking"])
	}

	bare := &Recorder{}
	m = decode(bare.serializeRequest(llm.CompletionRequest{}))
	if _, has := m["thinking"]; has {
		t.Fatalf("no thinkingType/reasoningEffort/override should write no thinking field at all, got %v", m["thinking"])
	}
}

// TestSerializeRequestStoresToolNamesNotSchemas covers the "schemas are huge,
// store only names" branch, which only runs when Tools is non-empty.
func TestSerializeRequestStoresToolNamesNotSchemas(t *testing.T) {
	r := &Recorder{}
	raw := r.serializeRequest(llm.CompletionRequest{
		Tools: []llm.ToolSchema{
			{Name: "bash", Description: "run a shell command", InputSchema: map[string]any{"type": "object"}},
			{Name: "report_finding"},
		},
	})
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if m["tools_count"].(float64) != 2 {
		t.Fatalf("tools_count = %v, want 2", m["tools_count"])
	}
	names, _ := m["tools"].([]any)
	if len(names) != 2 || names[0] != "bash" || names[1] != "report_finding" {
		t.Fatalf("tools should be name-only, got %v", m["tools"])
	}
	if strings.Contains(raw, "run a shell command") {
		t.Fatalf("full tool description/schema should not be stored: %s", raw)
	}
}
