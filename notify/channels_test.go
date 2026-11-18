package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// singleMsg builds a single-send message with quotes and newlines. Deliberately
// uses a title/summary containing `"` and `\n`: exactly the input that most
// easily produces invalid JSON from template interpolation.
func singleMsg() Message {
	return Message{
		Items: []Item{{
			FindingID: 42,
			Name:      `login page "SQL injection" risk`,
			VulnClass: "SQL injection",
			Severity:  "high",
			Summary:   "param id\nunfiltered leads to injection",
			Assets:    []string{"a.example.com", "b.example.com"},
			DetailURL: "https://artex.local/function/findings/detail?id=42",
		}},
	}
}

// batchMsg builds a batch digest message.
func batchMsg(n int) Message {
	m := Message{Batch: true, WindowMinutes: 30, HomeURL: "https://artex.local/function/findings"}
	for i := 0; i < n; i++ {
		m.Items = append(m.Items, Item{
			FindingID: int64(i + 1),
			Name:      "vuln" + itoa(i+1),
			VulnClass: "XSS",
			Severity:  "medium",
			Summary:   "reflected cross-site scripting",
			Assets:    []string{"target.example.com"},
		})
	}
	return m
}

// capturePost starts a fake receiver and hands the received request body and
// headers to the assertion function.
func capturePost(t *testing.T, respBody string, assert func(t *testing.T, body map[string]any, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("request body is not valid JSON: %v\nraw: %s", err, raw)
			}
		}
		if assert != nil {
			assert(t, body, r)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDingTalkSendsActionCardWhenLinkPresent(t *testing.T) {
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msgtype"] != "actionCard" {
			t.Fatalf("with a backlink it should send actionCard, got %v", body["msgtype"])
		}
		card, _ := body["actionCard"].(map[string]any)
		if card["singleURL"] != "https://artex.local/function/findings/detail?id=42" {
			t.Errorf("backlink lost: %v", card["singleURL"])
		}
	})
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestDingTalkFallsBackToMarkdownForBatch(t *testing.T) {
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msgtype"] != "markdown" {
			t.Fatalf("a batch message should send markdown, got %v", body["msgtype"])
		}
		md, _ := body["markdown"].(map[string]any)
		if !strings.Contains(md["text"].(string), "in the last 30 minutes") {
			t.Errorf("batch body missing the time window: %v", md["text"])
		}
	})
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, batchMsg(3)); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

// TestDingTalkBusinessErrorIsPermanent locks in the "HTTP 200 but errcode != 0"
// judgment. Not checking errcode would record failed deliveries as successful —
// a shared pitfall of the domestic IM platforms.
func TestDingTalkBusinessErrorIsPermanent(t *testing.T) {
	srv := capturePost(t, `{"errcode":310000,"errmsg":"keywords not in content"}`, nil)
	_, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg())
	if err == nil {
		t.Fatal("errcode != 0 should error")
	}
	if !IsPermanent(err) {
		t.Fatalf("keyword mismatch is a configuration error and should be marked permanent, got %v", err)
	}
	if !strings.Contains(err.Error(), "310000") {
		t.Errorf("the error should carry the platform error code, got %v", err)
	}
}

func TestWeComTruncatesCJKWithinByteLimit(t *testing.T) {
	var contentLen int
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		md, _ := body["markdown"].(map[string]any)
		content, _ := md["content"].(string)
		contentLen = len(content)
		if !utf8.ValidString(content) {
			t.Fatal("not valid UTF-8 after truncation — WeCom would reject the whole message")
		}
	})
	// Build a batch long enough to definitely exceed 4096 bytes.
	m := batchMsg(200)
	if _, err := (weComChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if contentLen > weComMarkdownLimit {
		t.Fatalf("body %d bytes exceeds the WeCom limit %d", contentLen, weComMarkdownLimit)
	}
	if contentLen == 0 {
		t.Fatal("body is empty")
	}
}

func TestWeComRateLimitIsRetryableButKeyErrorIsPermanent(t *testing.T) {
	limited := capturePost(t, `{"errcode":45009,"errmsg":"api freq out of limit"}`, nil)
	_, err := (weComChannel{}).Send(context.Background(), map[string]any{"webhook": limited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("45009 is rolling-window rate limiting, should be retryable, got %v", err)
	}

	badKey := capturePost(t, `{"errcode":93000,"errmsg":"invalid webhook url"}`, nil)
	_, err = (weComChannel{}).Send(context.Background(), map[string]any{"webhook": badKey.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("93000 is an invalid key; retries will not fix it, should be permanent, got %v", err)
	}
}

func TestFeishuCardStructureAndSign(t *testing.T) {
	const secret = "SECtest123"
	srv := capturePost(t, `{"code":0,"msg":"success"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msg_type"] != "interactive" {
			t.Fatalf("should send an interactive card, got %v", body["msg_type"])
		}
		card, _ := body["card"].(map[string]any)
		header, _ := card["header"].(map[string]any)
		if header["template"] != "orange" {
			t.Errorf("high severity should use the orange color, got %v", header["template"])
		}
		// With a secret configured the signing params must be present, otherwise
		// Feishu rejects with 19021.
		if body["sign"] == nil || body["timestamp"] == nil {
			t.Fatalf("missing signing parameters: %v", body)
		}
		// The card elements should include a button whose url points to the
		// finding details.
		elements, _ := card["elements"].([]any)
		foundButton := false
		for _, e := range elements {
			em, _ := e.(map[string]any)
			if em["tag"] != "action" {
				continue
			}
			actions, _ := em["actions"].([]any)
			for _, a := range actions {
				am, _ := a.(map[string]any)
				if am["url"] == "https://artex.local/function/findings/detail?id=42" {
					foundButton = true
				}
			}
		}
		if !foundButton {
			t.Fatal("no button pointing to the detail page in the card")
		}
	})
	cfg := map[string]any{"webhook": srv.URL, "secret": secret}
	if _, err := (feishuChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestFeishuWithoutSecretOmitsSign(t *testing.T) {
	srv := capturePost(t, `{"code":0,"msg":"success"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["sign"] != nil || body["timestamp"] != nil {
			t.Fatalf("signing params must not be present when no secret is configured: %v", body)
		}
	})
	if _, err := (feishuChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestTelegramEscapesHTMLInUntrustedContent(t *testing.T) {
	var text string
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		text, _ = body["text"].(string)
		if body["parse_mode"] != "HTML" {
			t.Fatalf("should use HTML parse mode, got %v", body["parse_mode"])
		}
	})
	m := Message{Items: []Item{{
		Severity: "high",
		// The title and summary come from the tested target / model output —
		// untrusted content.
		Name:    `<script>alert(1)</script>`,
		Summary: "a & b < c",
	}}}
	if _, err := (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if strings.Contains(text, "<script>") {
		t.Fatalf("HTML not escaped, injection possible: %q", text)
	}
	if !strings.Contains(text, "&lt;script&gt;") {
		t.Fatalf("expected escaped entities, got %q", text)
	}
	if !strings.Contains(text, "a &amp; b") {
		t.Fatalf("& not escaped, got %q", text)
	}
}

func TestTelegramErrorClassification(t *testing.T) {
	rateLimited := capturePost(t, `{"ok":false,"error_code":429,"description":"Too Many Requests"}`, nil)
	_, err := (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": rateLimited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("429 should be retryable, got %v", err)
	}

	forbidden := capturePost(t, `{"ok":false,"error_code":403,"description":"bot was blocked by the user"}`, nil)
	_, err = (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": forbidden.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("403 is a configuration problem, should be permanent, got %v", err)
	}
}

func TestSlackEscapesMrkdwnLinkInjection(t *testing.T) {
	var text string
	srv := capturePost(t, `ok`, func(t *testing.T, body map[string]any, _ *http.Request) {
		text, _ = body["text"].(string)
	})
	m := Message{Items: []Item{{
		Severity: "high",
		// Untrusted content (model output / target response) trying to forge a
		// clickable Slack link via mrkdwn's <url|text> syntax.
		Name:    "SQLi <https://evil.example.com|URGENT: verify your account>",
		Summary: "a & b < c",
	}}}
	if _, err := (slackChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if strings.Contains(text, "<https://evil.example.com|") {
		t.Fatalf("mrkdwn link injection not escaped: %q", text)
	}
	if !strings.Contains(text, "&lt;https://evil.example.com|") {
		t.Fatalf("expected escaped entities, got %q", text)
	}
	if !strings.Contains(text, "a &amp; b &lt; c") {
		t.Fatalf("& and < not escaped, got %q", text)
	}
}

func TestSlackBatchIncludesBacklink(t *testing.T) {
	var text string
	srv := capturePost(t, `ok`, func(t *testing.T, body map[string]any, _ *http.Request) {
		text, _ = body["text"].(string)
	})
	if _, err := (slackChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, batchMsg(3)); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if !strings.Contains(text, "Last 30 min") {
		t.Errorf("batch body missing the time window: %q", text)
	}
	if !strings.Contains(text, "<https://artex.local/function/findings|View all on the platform>") {
		t.Errorf("batch body missing the backlink: %q", text)
	}
}

// TestSlackReportsRealStatusCodes locks in the one trait that sets Slack apart
// from DingTalk/WeCom/Telegram: delivery failures surface as an HTTP status,
// not a 200 with a business errcode, so doJSON's existing classification needs
// no business-error unwrapping for this channel.
func TestSlackReportsRealStatusCodes(t *testing.T) {
	rateLimited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "rate_limited")
	}))
	t.Cleanup(rateLimited.Close)
	_, err := (slackChannel{}).Send(context.Background(), map[string]any{"webhook": rateLimited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("429 should be retryable, got %v", err)
	}

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "no_service")
	}))
	t.Cleanup(notFound.Close)
	_, err = (slackChannel{}).Send(context.Background(), map[string]any{"webhook": notFound.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("404 (bad webhook) is a configuration error, should be permanent, got %v", err)
	}
}

func TestDiscordSuppressesMentionsAndEscapesMarkdown(t *testing.T) {
	var body map[string]any
	srv := capturePost(t, `{}`, func(t *testing.T, b map[string]any, _ *http.Request) {
		body = b
	})
	m := Message{Items: []Item{{
		Severity: "high",
		// Untrusted content (model output / target response) trying to ping
		// the whole server via a literal mention token.
		Name:    "RCE @everyone <@&123456> go look now",
		Summary: "uses * and _ and ~ and | formatting chars",
	}}}
	if _, err := (discordChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	allowed, ok := body["allowed_mentions"].(map[string]any)
	if !ok {
		t.Fatalf("allowed_mentions missing from payload: %v", body)
	}
	parse, _ := allowed["parse"].([]any)
	if len(parse) != 0 {
		t.Fatalf("allowed_mentions.parse should be empty (suppress everything), got %v", parse)
	}
	content, _ := body["content"].(string)
	// The mention text itself is still visible (Discord's allowed_mentions
	// only controls whether it *pings*, not whether it renders), but markdown
	// metacharacters from untrusted content must be neutralized.
	if !strings.Contains(content, "@everyone") {
		t.Fatalf("mention text unexpectedly stripped: %q", content)
	}
	if strings.Contains(content, "uses * and") {
		t.Fatalf("markdown metacharacters not escaped: %q", content)
	}
}

func TestDiscordTruncatesToContentLimit(t *testing.T) {
	var content string
	srv := capturePost(t, `{}`, func(t *testing.T, b map[string]any, _ *http.Request) {
		content, _ = b["content"].(string)
	})
	// Build a batch long enough to definitely exceed the 2000-character limit.
	m := batchMsg(200)
	if _, err := (discordChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if n := utf8.RuneCountInString(content); n > discordTextLimit {
		t.Fatalf("content %d runes exceeds Discord's %d limit", n, discordTextLimit)
	}
	if content == "" {
		t.Fatal("content is empty")
	}
}

func TestDiscordReportsRealStatusCodes(t *testing.T) {
	rateLimited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"message":"rate limited","retry_after":1.0}`)
	}))
	t.Cleanup(rateLimited.Close)
	_, err := (discordChannel{}).Send(context.Background(), map[string]any{"webhook": rateLimited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("429 should be retryable, got %v", err)
	}

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Unknown Webhook","code":10015}`)
	}))
	t.Cleanup(notFound.Close)
	_, err = (discordChannel{}).Send(context.Background(), map[string]any{"webhook": notFound.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("404 (unknown webhook) is a configuration error, should be permanent, got %v", err)
	}
}

// withPagerDutyEndpoint points pagerDutyEndpoint at an httptest server for the
// duration of the test. PagerDuty is the one channel with no per-config URL
// to redirect (see the pagerDutyEndpoint doc comment), so the fixed endpoint
// itself must be swapped instead.
func withPagerDutyEndpoint(t *testing.T, url string) {
	t.Helper()
	orig := pagerDutyEndpoint
	pagerDutyEndpoint = url
	t.Cleanup(func() { pagerDutyEndpoint = orig })
}

func TestPagerDutyTriggerCarriesDedupKeyAndSeverity(t *testing.T) {
	var body map[string]any
	srv := capturePost(t, `{"status":"success","dedup_key":"x"}`, func(t *testing.T, b map[string]any, r *http.Request) {
		body = b
	})
	withPagerDutyEndpoint(t, srv.URL)
	if _, err := (pagerDutyChannel{}).Send(context.Background(), map[string]any{"routing_key": "rk"}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if body["event_action"] != "trigger" {
		t.Fatalf("expected trigger, got %v", body["event_action"])
	}
	if body["dedup_key"] != "artex-finding-42" {
		t.Fatalf("dedup_key wrong: %v", body["dedup_key"])
	}
	payload, _ := body["payload"].(map[string]any)
	if payload["severity"] != "error" { // singleMsg() uses severity "high"
		t.Fatalf("severity mapping wrong: %v", payload["severity"])
	}
	if body["routing_key"] != "rk" {
		t.Fatalf("routing_key lost: %v", body["routing_key"])
	}
}

// TestPagerDutyStatusChangeToClosedResolves is the one behavior that is not
// just text rendering: closing a finding must resolve the PagerDuty incident
// its original trigger opened, using the same dedup_key, or the on-call
// incident stays open forever.
func TestPagerDutyStatusChangeToClosedResolves(t *testing.T) {
	cases := []struct {
		toStatus string
		resolves bool
	}{
		{"fixed", true}, {"resolved", true}, {"false_positive", true},
		{"duplicate", true}, {"risk_accepted", true}, {"ignored", true},
		{"confirmed", false}, {"in_progress", false}, {"pending", false},
	}
	for _, tc := range cases {
		var body map[string]any
		srv := capturePost(t, `{"status":"success"}`, func(t *testing.T, b map[string]any, _ *http.Request) { body = b })
		withPagerDutyEndpoint(t, srv.URL)
		m := Message{Items: []Item{{FindingID: 7, Severity: "high", FromStatus: "pending", ToStatus: tc.toStatus}}}
		if _, err := (pagerDutyChannel{}).Send(context.Background(), map[string]any{"routing_key": "rk"}, m); err != nil {
			t.Fatalf("toStatus=%s: delivery failed: %v", tc.toStatus, err)
		}
		wantAction := "trigger"
		if tc.resolves {
			wantAction = "resolve"
		}
		if body["event_action"] != wantAction {
			t.Errorf("toStatus=%s: event_action=%v, want %s", tc.toStatus, body["event_action"], wantAction)
		}
		if body["dedup_key"] != "artex-finding-7" {
			t.Errorf("toStatus=%s: dedup_key=%v, want artex-finding-7", tc.toStatus, body["dedup_key"])
		}
	}
}

// TestPagerDutyBatchBecomesOneIncidentNoDedupKey locks in the "one message,
// one HTTP request" invariant the rate limiter depends on (see
// server/notifier.go): a digest of N findings must still be exactly one
// enqueue call, not N, and since no single finding owns the incident it
// carries no dedup_key.
func TestPagerDutyBatchBecomesOneIncidentNoDedupKey(t *testing.T) {
	var body map[string]any
	calls := 0
	srv := capturePost(t, `{"status":"success"}`, func(t *testing.T, b map[string]any, _ *http.Request) {
		body = b
		calls++
	})
	withPagerDutyEndpoint(t, srv.URL)
	kept, err := (pagerDutyChannel{}).Send(context.Background(), map[string]any{"routing_key": "rk"}, batchMsg(5))
	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 HTTP request for the whole batch, got %d", calls)
	}
	if kept != 5 {
		t.Fatalf("kept = %d, want 5 (the whole batch is represented in the one incident)", kept)
	}
	if _, has := body["dedup_key"]; has {
		t.Fatalf("a digest incident must not carry a dedup_key, got %v", body["dedup_key"])
	}
	if body["event_action"] != "trigger" {
		t.Fatalf("expected trigger, got %v", body["event_action"])
	}
}

func TestPagerDutyReportsRealStatusCodes(t *testing.T) {
	rateLimited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"status":"rate limited"}`)
	}))
	t.Cleanup(rateLimited.Close)
	withPagerDutyEndpoint(t, rateLimited.URL)
	_, err := (pagerDutyChannel{}).Send(context.Background(), map[string]any{"routing_key": "rk"}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("429 should be retryable, got %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"status":"invalid event","errors":["routing_key not recognized"]}`)
	}))
	t.Cleanup(bad.Close)
	withPagerDutyEndpoint(t, bad.URL)
	_, err = (pagerDutyChannel{}).Send(context.Background(), map[string]any{"routing_key": "rk"}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("400 (bad routing key) is a configuration error, should be permanent, got %v", err)
	}
}

// withOpsgenieEndpoint points opsgenieEndpoint at an httptest server for the
// duration of the test, same reasoning as withPagerDutyEndpoint.
func withOpsgenieEndpoint(t *testing.T, url string) {
	t.Helper()
	orig := opsgenieEndpoint
	opsgenieEndpoint = url
	t.Cleanup(func() { opsgenieEndpoint = orig })
}

func TestOpsgenieCreateCarriesAliasAndAuthHeader(t *testing.T) {
	var body map[string]any
	var gotPath, gotAuth string
	srv := capturePost(t, `{"result":"Request will be processed"}`, func(t *testing.T, b map[string]any, r *http.Request) {
		body, gotPath, gotAuth = b, r.URL.Path, r.Header.Get("Authorization")
	})
	withOpsgenieEndpoint(t, srv.URL)
	if _, err := (opsgenieChannel{}).Send(context.Background(), map[string]any{"api_key": "k"}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if gotAuth != "GenieKey k" {
		t.Fatalf("Authorization header wrong: %q", gotAuth)
	}
	if gotPath != "" && gotPath != "/" {
		t.Fatalf("create should POST to the base endpoint, got path %q", gotPath)
	}
	if body["alias"] != "artex-finding-42" {
		t.Fatalf("alias wrong: %v", body["alias"])
	}
	if body["priority"] != "P2" { // singleMsg() uses severity "high"
		t.Fatalf("priority mapping wrong: %v", body["priority"])
	}
	if l := len(body["message"].(string)); l > opsgenieMessageLimit {
		t.Fatalf("message %d runes exceeds Opsgenie's %d limit", l, opsgenieMessageLimit)
	}
}

// TestOpsgenieStatusChangeRoutesByTerminality is the core design decision in
// this channel: a closed-status transition must hit the close endpoint, and
// every other status change must hit notes — never create again (see the
// opsgenieChannel doc comment on why create is not safe to repeat).
func TestOpsgenieStatusChangeRoutesByTerminality(t *testing.T) {
	cases := []struct {
		toStatus   string
		wantSuffix string
	}{
		{"fixed", "/artex-finding-9/close"},
		{"resolved", "/artex-finding-9/close"},
		{"confirmed", "/artex-finding-9/notes"},
		{"in_progress", "/artex-finding-9/notes"},
	}
	for _, tc := range cases {
		var gotPath string
		srv := capturePost(t, `{"result":"ok"}`, func(t *testing.T, _ map[string]any, r *http.Request) { gotPath = r.URL.Path })
		withOpsgenieEndpoint(t, srv.URL)
		m := Message{Items: []Item{{FindingID: 9, Severity: "high", FromStatus: "pending", ToStatus: tc.toStatus}}}
		if _, err := (opsgenieChannel{}).Send(context.Background(), map[string]any{"api_key": "k"}, m); err != nil {
			t.Fatalf("toStatus=%s: delivery failed: %v", tc.toStatus, err)
		}
		if gotPath != tc.wantSuffix {
			t.Errorf("toStatus=%s: path=%q, want %q", tc.toStatus, gotPath, tc.wantSuffix)
		}
	}
}

// TestOpsgenieRepeatedTestSendsDoNotCollide is the end-to-end regression for
// the bug alertCorrelationKey's findingID==0 special case fixes: the
// server's "Test" button always sends FindingID 0 (notifyTestMessage), and
// without a fresh alias per call, a second test click would create-alert
// against the alias the first click's still-open test alert already holds —
// which Opsgenie rejects with 409, making a perfectly valid config look
// broken on the second click.
func TestOpsgenieRepeatedTestSendsDoNotCollide(t *testing.T) {
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		alias, _ := body["alias"].(string)
		if alias != "" && seen[alias] {
			// This is exactly the behavior Opsgenie's real API would show:
			// a second create against an alias with an already-open alert.
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"message":"already exists"}`)
			return
		}
		seen[alias] = true
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"result":"ok"}`)
	}))
	t.Cleanup(srv.Close)
	withOpsgenieEndpoint(t, srv.URL)

	testMsg := Message{Items: []Item{{FindingID: 0, Name: "Test message", Severity: "low"}}}
	for i := 0; i < 3; i++ {
		if _, err := (opsgenieChannel{}).Send(context.Background(), map[string]any{"api_key": "k"}, testMsg); err != nil {
			t.Fatalf("test send #%d failed: %v", i+1, err)
		}
	}
}

func TestOpsgenieBatchIsOneAlertNoAlias(t *testing.T) {
	var body map[string]any
	calls := 0
	srv := capturePost(t, `{"result":"ok"}`, func(t *testing.T, b map[string]any, _ *http.Request) { body, calls = b, calls+1 })
	withOpsgenieEndpoint(t, srv.URL)
	kept, err := (opsgenieChannel{}).Send(context.Background(), map[string]any{"api_key": "k"}, batchMsg(5))
	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 HTTP request for the whole batch, got %d", calls)
	}
	if kept != 5 {
		t.Fatalf("kept = %d, want 5", kept)
	}
	if _, has := body["alias"]; has {
		t.Fatalf("a digest alert must not carry an alias, got %v", body["alias"])
	}
}

func TestOpsgenieReportsRealStatusCodes(t *testing.T) {
	rateLimited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"message":"rate limited"}`)
	}))
	t.Cleanup(rateLimited.Close)
	withOpsgenieEndpoint(t, rateLimited.URL)
	_, err := (opsgenieChannel{}).Send(context.Background(), map[string]any{"api_key": "k"}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("429 should be retryable, got %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"API key is invalid"}`)
	}))
	t.Cleanup(bad.Close)
	withOpsgenieEndpoint(t, bad.URL)
	_, err = (opsgenieChannel{}).Send(context.Background(), map[string]any{"api_key": "k"}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("401 (bad api key) is a configuration error, should be permanent, got %v", err)
	}
}

func TestWebhookDefaultTemplateProducesValidJSON(t *testing.T) {
	// This case is the whole point of the default template: when the title
	// contains quotes and newlines, any naive `"title": "{{.Title}}"` produces
	// invalid JSON. {{json .}} does not.
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["title"] != `[🟠 High] login page "SQL injection" risk` {
			t.Errorf("title not restored correctly: %v", body["title"])
		}
		items, _ := body["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("items should have 1 entry, got %d", len(items))
		}
		it, _ := items[0].(map[string]any)
		if it["summary"] != "param id\nunfiltered leads to injection" {
			t.Errorf("summary not restored correctly: %v", it["summary"])
		}
		// The number must be a JSON number, not a string (json:"...,string" style
		// tags hit this pitfall).
		if _, ok := it["finding_id"].(float64); !ok {
			t.Errorf("finding_id should be a number, got %T", it["finding_id"])
		}
	})
	if _, err := (webhookChannel{}).Send(context.Background(), map[string]any{"url": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestWebhookCustomTemplateAndHeaders(t *testing.T) {
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, r *http.Request) {
		if r.Header.Get("X-Token") != "s3cret" {
			t.Errorf("custom header lost: %v", r.Header)
		}
		if body["msg"] != "3 items" {
			t.Errorf("custom template rendered incorrectly: %v", body["msg"])
		}
		if body["first"] != "vuln1" {
			t.Errorf("range extraction wrong: %v", body["first"])
		}
	})
	cfg := map[string]any{
		"url":           srv.URL,
		"headers":       map[string]any{"X-Token": "s3cret"},
		"body_template": `{"msg": {{json (printf "%d items" .Count)}}, "first": {{json (index .Items 0).Name}}}`,
	}
	if _, err := (webhookChannel{}).Send(context.Background(), cfg, batchMsg(3)); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestWebhookRejectsNonJSONRenderResult(t *testing.T) {
	cfg := map[string]any{"url": "https://example.com/hook", "body_template": `not json at all`}
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a non-JSON render result should be a permanent failure (the template is wrong; retrying is useless), got %v", err)
	}
}

func TestWebhookValidateCatchesBadConfigEarly(t *testing.T) {
	bad := []map[string]any{
		{},
		{"url": "file:///etc/passwd"},
		{"url": "https://example.com", "method": "DELETE"},
		{"url": "https://example.com", "body_template": `{{.Items.`},
	}
	for i, cfg := range bad {
		if err := (webhookChannel{}).Validate(cfg); err == nil {
			t.Errorf("config set %d should be rejected: %v", i, cfg)
		}
	}
}

func TestEmailMessageIsWellFormed(t *testing.T) {
	msg, err := buildEmailMessage("artex@example.com", []string{"a@example.com", "b@example.com"}, singleMsg())
	if err != nil {
		t.Fatalf("failed to build the email: %v", err)
	}
	if !strings.HasPrefix(msg, "From: artex@example.com\r\n") {
		t.Fatalf("bad From header:\n%s", msg)
	}
	if !strings.Contains(msg, "To: a@example.com, b@example.com\r\n") {
		t.Fatalf("bad To header:\n%s", msg)
	}
	// A non-ASCII subject must be RFC 2047 encoded, otherwise clients display it
	// as mojibake.
	if !strings.Contains(msg, "Subject: =?utf-8?") {
		t.Fatalf("subject not RFC 2047 encoded:\n%s", msg)
	}
	if dec, err := new(mime.WordDecoder).DecodeHeader(mustExtractHeader(t, msg, "Subject")); err != nil {
		t.Fatalf("subject cannot be decoded: %v", err)
	} else if !strings.Contains(dec, "SQL injection") {
		t.Fatalf("decoded subject content wrong: %q", dec)
	}

	// The body is base64; decoded it should be valid HTML.
	parts := strings.SplitN(msg, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatal("email missing the header/body separator")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(parts[1]), "\r\n", ""))
	if err != nil {
		t.Fatalf("body base64 decode failed: %v", err)
	}
	html := string(decoded)
	if !strings.HasPrefix(html, "<div") {
		t.Fatalf("body is not HTML: %.80s", html)
	}
	// The title appears verbatim in the text position: double quotes are legal
	// characters in HTML text content and need no escaping. Asserting "kept
	// verbatim" here guards against a future misguided quote-escaping layer that
	// would render the quotes as &quot;.
	if !strings.Contains(html, `"SQL injection"`) {
		t.Fatalf("quotes in the title should be kept verbatim in the text position: %.200s", html)
	}
}

// TestEmailEscapesStructuralInjection covers the injections the email body
// really must defend against: the finding title and summary come from the
// tested target and model output — untrusted content. Text positions must
// escape & < > (otherwise tags can be injected), and attribute positions must
// also escape quotes (otherwise an href can be closed).
func TestEmailEscapesStructuralInjection(t *testing.T) {
	m := Message{
		Items: []Item{{
			Severity:  "high",
			Name:      `<script>alert(1)</script>`,
			Summary:   "a & b > c",
			DetailURL: `https://artex.local/x?a="onmouseover=alert(1)`,
		}},
	}
	html := htmlBody(m, 0)
	if strings.Contains(html, "<script>") {
		t.Fatalf("title not escaped, tag injection possible: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("expected escaped entities: %s", html)
	}
	if !strings.Contains(html, "a &amp; b &gt; c") {
		t.Fatalf("& and > not escaped: %s", html)
	}
	// The backlink is the admin-configurable public_base_url, fairly trustworthy
	// itself, but attribute positions must still escape quotes — otherwise an
	// address containing a quote would close the href and inject an event handler.
	if strings.Contains(html, `onmouseover=alert(1)">`) {
		t.Fatalf("href attribute not escaped correctly: %s", html)
	}
	if !strings.Contains(html, "&quot;") {
		t.Fatalf("quotes in attribute positions should be escaped: %s", html)
	}
}

func mustExtractHeader(t *testing.T, msg, name string) string {
	t.Helper()
	for _, line := range strings.Split(msg, "\r\n") {
		if strings.HasPrefix(line, name+": ") {
			return strings.TrimPrefix(line, name+": ")
		}
	}
	t.Fatalf("header %s not found", name)
	return ""
}

func TestChannelValidateReportsMissingFields(t *testing.T) {
	// Validation errors are shown directly to the configurator; they must say
	// what is missing, not a vague "invalid config".
	cases := []struct {
		kind   string
		cfg    map[string]any
		substr string
	}{
		{KindDingTalk, map[string]any{}, "Webhook"},
		{KindFeishu, map[string]any{}, "Webhook"},
		{KindWeCom, map[string]any{}, "Webhook"},
		{KindTelegram, map[string]any{}, "Bot Token"},
		{KindTelegram, map[string]any{"bot_token": "t"}, "Chat ID"},
		{KindSlack, map[string]any{}, "Webhook"},
		{KindDiscord, map[string]any{}, "Webhook"},
		{KindPagerDuty, map[string]any{}, "Routing Key"},
		{KindOpsgenie, map[string]any{}, "API Key"},
		{KindEmail, map[string]any{}, "SMTP"},
		{KindEmail, map[string]any{"host": "h"}, "port"},
		{KindEmail, map[string]any{"host": "h", "port": 587, "from": "f"}, "recipient"},
	}
	for _, tc := range cases {
		ch, ok := Get(tc.kind)
		if !ok {
			t.Fatalf("channel %s not registered", tc.kind)
		}
		err := ch.Validate(tc.cfg)
		if err == nil {
			t.Errorf("%s config %v should fail validation", tc.kind, tc.cfg)
			continue
		}
		if !strings.Contains(err.Error(), tc.substr) {
			t.Errorf("%s's error message should mention %q, got %q", tc.kind, tc.substr, err.Error())
		}
	}
}

// TestEmailSMTPErrorClassification locks in the SMTP 4xx/5xx semantic
// distinction. If 4xx were also judged permanent, a greylisting mail server
// would drop every push into failed after the first attempt — and greylisting
// is exactly where automatic retry should shine.
func TestEmailSMTPErrorClassification(t *testing.T) {
	cases := []struct {
		reply     string
		permanent bool
	}{
		{"450 4.7.1 Greylisting in action, please come back later", false},
		{"451 4.3.0 Temporary system failure", false},
		{"452 4.2.2 Mailbox full", false},
		{"550 5.1.1 User unknown", true},
		{"553 5.1.3 Bad address syntax", true},
		{"554 5.7.1 Relay access denied", true},
		// When no reply code can be extracted, treat as "retryable": better one
		// extra try than condemning a possibly transient failure.
		{"unexpected EOF", false},
		{"", false},
	}
	for _, tc := range cases {
		err := smtpStageError("recipient rejected", errors.New(tc.reply))
		if got := IsPermanent(err); got != tc.permanent {
			t.Errorf("reply %q: want permanent=%v got %v", tc.reply, tc.permanent, got)
		}
		// Whatever the classification, the original text must be preserved for
		// troubleshooting.
		if tc.reply != "" && !strings.Contains(err.Error(), tc.reply) {
			t.Errorf("the original text of reply %q was dropped: %v", tc.reply, err)
		}
	}
}

func TestRegistryCoversAllKinds(t *testing.T) {
	// All ten channels are required — a missing one would silently vanish from
	// the UI dropdown.
	want := []string{KindDingTalk, KindDiscord, KindEmail, KindFeishu, KindOpsgenie, KindPagerDuty, KindSlack, KindTelegram, KindWebhook, KindWeCom}
	got := Kinds()
	if len(got) != len(want) {
		t.Fatalf("channel count should be %d, got %d: %v", len(want), len(got), got)
	}
	for _, k := range want {
		if !ValidKind(k) {
			t.Errorf("channel %s not registered", k)
		}
		if ch, ok := Get(k); !ok || ch.Kind() != k {
			t.Errorf("channel %s's Kind() does not match the registry key", k)
		}
	}
	if ValidKind("nope") {
		t.Error("an unregistered type should not pass validation")
	}
}

func TestPermanentErrorUnwrap(t *testing.T) {
	base := &permanentSentinel{}
	err := Permanent(base)
	if !IsPermanent(err) {
		t.Fatal("should be recognized as permanent")
	}
	if !strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("the error message should pass through the underlying one: %v", err)
	}
	if Permanent(nil) != nil {
		t.Fatal("Permanent(nil) must return nil")
	}
	if IsPermanent(nil) {
		t.Fatal("nil is not a permanent failure")
	}
}

type permanentSentinel struct{}

func (*permanentSentinel) Error() string { return "sentinel" }
