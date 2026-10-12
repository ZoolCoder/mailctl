package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// mcpSession sends each request line to a fresh server and decodes the replies.
func mcpSession(t *testing.T, lines ...string) []rpcResponse {
	t.Helper()
	var out bytes.Buffer
	if err := runMCP(strings.NewReader(strings.Join(lines, "\n")), &out); err != nil {
		t.Fatalf("runMCP: %v", err)
	}
	var replies []rpcResponse
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r rpcResponse
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode reply: %v\n%s", err, out.String())
		}
		replies = append(replies, r)
	}
	return replies
}

// callTool runs one tools/call and returns the text and whether it is an error.
func callTool(t *testing.T, name string, args map[string]any) (string, bool) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args}})
	replies := mcpSession(t, string(raw))
	if len(replies) != 1 || replies[0].Error != nil {
		t.Fatalf("tools/call %s: %+v", name, replies)
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	b, _ := json.Marshal(replies[0].Result)
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	return result.Content[0].Text, result.IsError
}

func TestMCPListsToolsWithAnnotationsAndSkillPrompts(t *testing.T) {
	replies := mcpSession(t,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"prompts/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"mail-setup"}}`)
	if len(replies) != 4 {
		t.Fatalf("got %d replies, want 4 (the notification gets none)", len(replies))
	}
	tools, _ := json.Marshal(replies[1].Result)
	for _, want := range []string{`"mail_plan"`, `"mail_apply"`, `"readOnlyHint":true`, `"destructiveHint":true`} {
		if !bytes.Contains(tools, []byte(want)) {
			t.Errorf("tools/list lacks %s", want)
		}
	}
	for _, refused := range []string{`"run"`, `"mailbox_passwd"`, `"apppass_rm"`} {
		if bytes.Contains(tools, []byte(refused)) {
			t.Errorf("tools/list exposes %s", refused)
		}
	}
	prompts, _ := json.Marshal(replies[2].Result)
	if !bytes.Contains(prompts, []byte(`"mailctl-setup"`)) {
		t.Errorf("prompts/list = %s", prompts)
	}
	prompt, _ := json.Marshal(replies[3].Result)
	if !bytes.Contains(prompt, []byte("Onboard a domain")) {
		t.Errorf("prompts/get mail-setup = %s", prompt)
	}
}

func TestMCPPlanThenApply(t *testing.T) {
	server := fakeServer(t)
	t.Setenv("MAILCTL_CONFIG", writeTestConfig(t, server.URL))
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")
	mcpMode = true
	t.Cleanup(func() { mcpMode = false })

	text, isError := callTool(t, "mail_plan", map[string]any{"domain": []any{"test.com"}})
	if isError {
		t.Fatalf("mail_plan: %s", text)
	}
	var planned struct {
		PlanID string `json:"plan_id"`
	}
	if err := json.Unmarshal([]byte(text), &planned); err != nil || planned.PlanID == "" {
		t.Fatalf("mail_plan reply is not {plan_id, plan}: %v\n%s", err, text)
	}

	text, isError = callTool(t, "mail_apply", map[string]any{"plan_id": planned.PlanID})
	if isError {
		t.Fatalf("mail_apply: %s", text)
	}
	if strings.Contains(text, "box@test.com\t") {
		t.Errorf("generated credential in the MCP reply:\n%s", text)
	}
}

func TestMCPApplyRejectsAPlanIDThatIsAPath(t *testing.T) {
	text, isError := callTool(t, "mail_apply", map[string]any{"plan_id": "../../etc/passwd"})
	if !isError || !strings.Contains(text, "not one mail_plan returned") {
		t.Errorf("mail_apply with a path: %s", text)
	}
}

func TestMCPRejectsAPositionalThatLooksLikeAFlag(t *testing.T) {
	text, isError := callTool(t, "mailbox_rm", map[string]any{"address": "-prune"})
	if !isError || !strings.Contains(text, "not valid") {
		t.Errorf("mailbox_rm -prune: %s", text)
	}
}

func TestMCPAppCredentialNeverReachesTheReply(t *testing.T) {
	server := fakeServer(t)
	t.Setenv("MAILCTL_CONFIG", writeTestConfig(t, server.URL))
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")
	mcpMode = true
	t.Cleanup(func() { mcpMode = false })

	text, isError := callTool(t, "apppass_create", map[string]any{"address": "box@test.com", "name": "phone"})
	if isError {
		t.Fatalf("apppass_create: %s", text)
	}
	if strings.Contains(text, "generated-app-pw") {
		t.Errorf("credential in the MCP reply:\n%s", text)
	}
	if !strings.Contains(text, "Wrote 1 generated credential(s) to ") {
		t.Errorf("reply should name where the credential went:\n%s", text)
	}
}
