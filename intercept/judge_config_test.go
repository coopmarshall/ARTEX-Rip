package intercept

import "testing"

// GetJudgeConfig/SetJudgeConfig had no dedicated test (0% coverage even
// across the full suite, confirmed via -coverpkg against server/'s
// integration tests too). These cover the round-trip and the two
// deliberate defaulting behaviors documented on judgeConfig.

func TestJudgeConfigRoundTripsThroughSetAndGet(t *testing.T) {
	d := targetTestDB(t)
	ic := New(d)
	original := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetJudgeConfig(original) })

	want := JudgeConfig{
		Enabled: true, ProfileID: 7, Prompt: "custom judge prompt",
		TimeoutSeconds: 42, FailAction: "deny",
		AskTimeoutSeconds: 99, AskTimeoutAction: "allow",
	}
	if err := ic.SetJudgeConfig(want); err != nil {
		t.Fatal(err)
	}
	got := ic.GetJudgeConfig()
	if got != want {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestJudgeConfigEmptyPromptFallsBackToBuiltinTemplate(t *testing.T) {
	d := targetTestDB(t)
	ic := New(d)
	original := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetJudgeConfig(original) })

	c := original
	c.Prompt = ""
	if err := ic.SetJudgeConfig(c); err != nil {
		t.Fatal(err)
	}
	got := ic.GetJudgeConfig()
	if got.Prompt != DefaultJudgePrompt {
		t.Fatalf("empty Prompt should fall back to DefaultJudgePrompt, got %q", got.Prompt)
	}
}

// TestJudgeConfigDoesNotSelfValidateActionFields documents, rather than
// fixes, a gap: SetJudgeConfig stores FailAction/AskTimeoutAction as given,
// with no validation against the allowed choice sets ("allow"/"ask"/"deny"
// and "allow"/"deny"). The only wired caller (server/intercept.go's
// interceptSetJudgeConfig) does validate before calling this, so it is not
// reachable through the one HTTP path today -- but a future direct caller
// would hit a confusing failure mode: Set succeeds with no error, while the
// invalid value is silently never honored because judgeConfig's read side
// (getSettingChoice) falls back to the default for anything outside the
// allowed set. Not changed here: intercept/ is safety-adjacent (this is the
// LLM-fallback-judge config) and the one reachable path is already correct.
func TestJudgeConfigDoesNotSelfValidateActionFields(t *testing.T) {
	d := targetTestDB(t)
	ic := New(d)
	original := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetJudgeConfig(original) })

	c := original
	c.FailAction = "not-a-real-action"
	if err := ic.SetJudgeConfig(c); err != nil {
		t.Fatalf("SetJudgeConfig with an invalid FailAction returned an error (if this now validates, update this test): %v", err)
	}
	got := ic.GetJudgeConfig()
	if got.FailAction != defaultJudgeFailAction {
		t.Fatalf("invalid FailAction should silently read back as the default %q, got %q", defaultJudgeFailAction, got.FailAction)
	}
}
