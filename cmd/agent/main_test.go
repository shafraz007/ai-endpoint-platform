package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/agent"
	"github.com/shafraz007/ai-endpoint-platform/internal/ai"
	"github.com/shafraz007/ai-endpoint-platform/internal/config"
)

func resetPersonalChatMemoryForTest() {
	personalChatMemoryMu.Lock()
	defer personalChatMemoryMu.Unlock()
	personalChatMemory = nil
}

func TestIsExplicitPingCommand(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "explicit ping", input: "ping google dns", want: true},
		{name: "please ping ip", input: "please ping 8.8.8.8", want: true},
		{name: "can you ping host", input: "can you ping sp.parcelat.com", want: true},
		{name: "slash ping", input: "/ping 8.8.8.8", want: true},
		{name: "non ping", input: "install pending updates", want: false},
		{name: "contains ping token in context", input: "I need help with ping latency", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExplicitPingCommand(tt.input)
			if got != tt.want {
				t.Fatalf("isExplicitPingCommand(%q)=%v want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInstallPendingUpdatesIntent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "install pending updates", input: "install pending updates", want: true},
		{name: "install all updates", input: "please install all updates", want: true},
		{name: "windows update install", input: "install windows update", want: true},
		{name: "query only", input: "are updates pending", want: false},
		{name: "unrelated", input: "how are you", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInstallPendingUpdatesRequest(tt.input)
			if got != tt.want {
				t.Fatalf("isInstallPendingUpdatesRequest(%q)=%v want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLooksLikeFabricatedCommandResult(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "command executed", input: "Command executed (ping -n 4 8.8.8.8):\n...", want: true},
		{name: "command failed", input: "Command execution failed (Get-Date /):\n...", want: true},
		{name: "normal reply", input: "I can help with that.", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeFabricatedCommandResult(tt.input)
			if got != tt.want {
				t.Fatalf("looksLikeFabricatedCommandResult(%q)=%v want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractCurrentUserMessage(t *testing.T) {
	tests := []struct {
		name        string
		instruction string
		want        string
	}{
		{
			name:        "wrapped instruction with memory",
			instruction: "Current user message:\ninstall pending updates\n\nConversation memory:\n- user: hi",
			want:        "install pending updates",
		},
		{
			name:        "case insensitive markers",
			instruction: "current user message: ping google dns\n\nconversation memory:\n- user: hello",
			want:        "ping google dns",
		},
		{
			name:        "memory does not override current message",
			instruction: "Current user message:\ninstall pending updates\n\nConversation memory:\nRecent turns:\n- user: ping google dns\n- assistant: Command executed (ping -n 4 8.8.8.8)",
			want:        "install pending updates",
		},
		{
			name:        "marker without memory section",
			instruction: "Current user message:\nhi there",
			want:        "hi there",
		},
		{
			name:        "plain instruction",
			instruction: "is device healthy?",
			want:        "is device healthy?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCurrentUserMessage(tt.instruction)
			if got != tt.want {
				t.Fatalf("extractCurrentUserMessage()=%q want %q", got, tt.want)
			}
		})
	}
}

func TestExecuteAITaskPersonalChatIgnoresMemoryCommands(t *testing.T) {
	task := ai.Task{
		TaskID:      "test-chat-memory-command",
		MotherRole:  ai.MotherInstructor,
		ChildIntent: ai.ChildSuggest,
		Title:       "Respond to personal chat",
		Instruction: "Current user message:\nhello there\n\nConversation memory:\nRecent turns:\n- user: ping google dns\n- assistant: Command executed (ping -n 4 8.8.8.8)",
		Context:     "personal_chat",
	}

	body, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("failed to marshal task: %v", err)
	}

	cfg := config.AgentConfig{}
	out, execErr := executeAITask(string(body), cfg, nil, nil)
	if execErr != nil {
		t.Fatalf("executeAITask returned error: %v", execErr)
	}

	var result ai.ChildResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if strings.Contains(strings.ToLower(result.Details), "command executed (ping") {
		t.Fatalf("unexpected command execution in details: %q", result.Details)
	}

	if strings.Contains(result.Details, "Conversation memory:") || strings.Contains(result.Details, "Current user message:") {
		t.Fatalf("unexpected memory wrapper leakage in details: %q", result.Details)
	}

	if strings.TrimSpace(result.Details) == "" {
		t.Fatalf("expected non-empty fallback response")
	}
}

func TestExecuteAITaskPersonalChatCurrentCommandStillExecutes(t *testing.T) {
	clearPendingCommandProposal()
	defer clearPendingCommandProposal()

	task := ai.Task{
		TaskID:      "test-chat-current-command",
		MotherRole:  ai.MotherInstructor,
		ChildIntent: ai.ChildSuggest,
		Title:       "Respond to personal chat",
		Instruction: "Current user message:\nshell: echo copilot-smoke\n\nConversation memory:\nRecent turns:\n- user: hi\n- assistant: hello",
		Context:     "personal_chat",
	}

	body, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("failed to marshal task: %v", err)
	}

	cfg := config.AgentConfig{CommandTimeout: 5 * time.Second}
	out, execErr := executeAITask(string(body), cfg, nil, nil)
	if execErr != nil {
		t.Fatalf("executeAITask returned error: %v", execErr)
	}

	var result ai.ChildResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	lower := strings.ToLower(result.Details)
	if !strings.Contains(lower, "reply with 'confirm'") {
		t.Fatalf("expected confirmation-gated response, got: %q", result.Details)
	}

	if !strings.Contains(lower, "echo copilot-smoke") {
		t.Fatalf("expected proposed command marker in details, got: %q", result.Details)
	}

	if strings.Contains(result.Details, "Conversation memory:") || strings.Contains(result.Details, "Current user message:") {
		t.Fatalf("unexpected memory wrapper leakage in details: %q", result.Details)
	}
}

func TestCommandConfirmationFlow(t *testing.T) {
	clearPendingCommandProposal()
	defer clearPendingCommandProposal()

	cfg := config.AgentConfig{CommandTimeout: 5 * time.Second}

	first, handled := tryHandlePersonalChatCommand("cmd: ping -n 4 8.8.8.8", cfg)
	if !handled {
		t.Fatalf("expected command proposal to be handled")
	}
	if !strings.Contains(strings.ToLower(first), "reply with 'confirm'") {
		t.Fatalf("expected confirmation prompt, got: %q", first)
	}

	confirm, handled := tryHandlePersonalChatCommand("confirm", cfg)
	if !handled {
		t.Fatalf("expected confirmation response to be handled")
	}
	if !strings.Contains(strings.ToLower(confirm), "command executed") {
		t.Fatalf("expected executed command response, got: %q", confirm)
	}
}

func TestCommandCancellationFlow(t *testing.T) {
	clearPendingCommandProposal()
	defer clearPendingCommandProposal()

	cfg := config.AgentConfig{CommandTimeout: 5 * time.Second}

	first, handled := tryHandlePersonalChatCommand("shell: echo should-not-run", cfg)
	if !handled {
		t.Fatalf("expected command proposal to be handled")
	}
	if !strings.Contains(strings.ToLower(first), "reply with 'confirm'") {
		t.Fatalf("expected confirmation prompt, got: %q", first)
	}

	cancel, handled := tryHandlePersonalChatCommand("cancel", cfg)
	if !handled {
		t.Fatalf("expected cancel response to be handled")
	}
	if !strings.Contains(strings.ToLower(cancel), "cancelled") {
		t.Fatalf("expected cancellation response, got: %q", cancel)
	}

	noPending, handled := tryHandlePersonalChatCommand("confirm", cfg)
	if handled {
		t.Fatalf("expected no-pending confirmation to fall back to normal chat, got handled response: %q", noPending)
	}
	if noPending != "" {
		t.Fatalf("expected empty direct response when no command is pending, got: %q", noPending)
	}
}

func TestExecutePersonalChatV2_ProposesExplicitCommand(t *testing.T) {
	clearPendingCommandProposal()
	defer clearPendingCommandProposal()

	task := &ai.Task{
		TaskID:      "v2-proposal",
		MotherRole:  ai.MotherInstructor,
		ChildIntent: ai.ChildSuggest,
		Context:     "personal_chat",
		Instruction: "Current user message:\ncmd: ping -n 4 8.8.8.8\n\nConversation memory:\n- user: hi\n- assistant: hello",
	}

	out, err := executePersonalChatV2(task, config.AgentConfig{CommandTimeout: 5 * time.Second}, nil, nil)
	if err != nil {
		t.Fatalf("executePersonalChatV2 returned error: %v", err)
	}

	var result ai.ChildResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if !strings.Contains(strings.ToLower(result.Details), "reply with 'confirm'") {
		t.Fatalf("expected confirmation-gated response, got: %q", result.Details)
	}
}

func TestExecuteAITask_PersonalChatV2_DefaultEngine(t *testing.T) {
	clearPendingCommandProposal()
	defer clearPendingCommandProposal()

	task := ai.Task{
		TaskID:      "v2-default-engine",
		MotherRole:  ai.MotherInstructor,
		ChildIntent: ai.ChildSuggest,
		Title:       "Respond to personal chat",
		Instruction: "Current user message:\nshell: echo v2-smoke\n\nConversation memory:\n- user: hi\n- assistant: hello",
		Context:     "personal_chat",
	}

	body, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("failed to marshal task: %v", err)
	}

	out, execErr := executeAITask(string(body), config.AgentConfig{CommandTimeout: 5 * time.Second}, nil, nil)
	if execErr != nil {
		t.Fatalf("executeAITask returned error: %v", execErr)
	}

	var result ai.ChildResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	lower := strings.ToLower(result.Details)
	if !strings.Contains(lower, "reply with 'confirm'") {
		t.Fatalf("expected confirmation-gated response, got: %q", result.Details)
	}
	if !strings.Contains(lower, "echo v2-smoke") {
		t.Fatalf("expected proposed command marker in details, got: %q", result.Details)
	}
}

func TestBuildPersonalChatFallbackReply(t *testing.T) {
	const wantUnavailable = "AI response is temporarily unavailable. Please try again in a moment."

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "greeting", input: "hi", want: wantUnavailable},
		{name: "acknowledgement", input: "good", want: wantUnavailable},
		{name: "how are you", input: "how are you", want: wantUnavailable},
		{name: "help", input: "what can you do", want: wantUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPersonalChatFallbackReply(tt.input, nil, nil)
			if got != tt.want {
				t.Fatalf("buildPersonalChatFallbackReply(%q)=%q want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildPersonalChatFallbackReply_HealthPriority(t *testing.T) {
	sysInfo := &agent.SystemInfo{
		Hostname:  "Venom",
		Processor: "Intel i7",
		Memory:    "31 GB",
	}
	osInfo := &agent.OSInfo{
		OSEdition: "Professional",
		OSVersion: "25H2",
		OSBuild:   "26200",
	}

	got := buildPersonalChatFallbackReply("can you help me understand the PC health", sysInfo, osInfo)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestIsCPUTemperatureRequest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "explicit cpu temperature", input: "whats the current cpu temperature", want: true},
		{name: "processor temp", input: "check processor temp", want: true},
		{name: "generic temperature", input: "what is current temperature", want: true},
		{name: "non temp", input: "how are you", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCPUTemperatureRequest(tt.input)
			if got != tt.want {
				t.Fatalf("isCPUTemperatureRequest(%q)=%v want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildCommandProposalCPUTemperature(t *testing.T) {
	proposal, ok, errText := buildCommandProposal("whats the current cpu temperature")
	if ok {
		t.Fatalf("expected cpu temperature request to NOT create proposal without explicit prefix")
	}
	if errText != "" {
		t.Fatalf("expected no error text for non-command input, got: %q", errText)
	}
	if proposal.CommandType != "" {
		t.Fatalf("expected empty command type, got %q", proposal.CommandType)
	}
	if proposal.Command != "" {
		t.Fatalf("expected empty command, got %q", proposal.Command)
	}
}

func TestBuildPersonalChatFallbackReply_TechnicianPingSuggestion(t *testing.T) {
	got := buildPersonalChatFallbackReply("can you ping google dns and check packet loss", nil, nil)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestBuildPersonalChatFallbackReply_TechnicianCPUSuggestion(t *testing.T) {
	got := buildPersonalChatFallbackReply("what is current cpu temperature", nil, nil)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestBuildPersonalChatFallbackReply_TechnicianEventViewerSuggestion(t *testing.T) {
	got := buildPersonalChatFallbackReply("please check event viewer for any recent error", nil, nil)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestIsEventViewerErrorRequest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "event viewer recent error", input: "please check event viewer for recent errors", want: true},
		{name: "event logs critical", input: "check windows logs critical events", want: true},
		{name: "unrelated", input: "how are you", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEventViewerErrorRequest(tt.input)
			if got != tt.want {
				t.Fatalf("isEventViewerErrorRequest(%q)=%v want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildPersonalChatFallbackReply_ExplainsPacketLossFromMemory(t *testing.T) {
	resetPersonalChatMemoryForTest()
	defer resetPersonalChatMemoryForTest()

	appendPersonalChatMemory("cmd: ping -n 4 8.8.8.8", "Command executed (ping -n 4 8.8.8.8):\nPing statistics for 8.8.8.8:\n    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\nApproximate round trip times in milli-seconds:\n    Minimum = 19ms, Maximum = 25ms, Average = 21ms")

	got := buildPersonalChatFallbackReply("explain the packet loss", nil, nil)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestBuildPersonalChatFallbackReply_ExplainsEventResultsFromMemory(t *testing.T) {
	resetPersonalChatMemoryForTest()
	defer resetPersonalChatMemoryForTest()

	appendPersonalChatMemory("powershell: Get-WinEvent ...", "Command executed (Get-WinEvent ...):\nTimeCreated  : 28/02/2026 04:30:56\nId           : 11\nProviderName : Microsoft-Windows-Security-Kerberos\nMessage      : Sample\n\nTimeCreated  : 27/02/2026 19:11:16\nId           : 10010\nProviderName : Microsoft-Windows-DistributedCOM\nMessage      : Sample")

	got := buildPersonalChatFallbackReply("please explain me the events results", nil, nil)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestBuildPersonalChatFallbackReply_GenericErrorExplainsEventMemory(t *testing.T) {
	resetPersonalChatMemoryForTest()
	defer resetPersonalChatMemoryForTest()

	appendPersonalChatMemory("powershell: Get-WinEvent ...", "Command executed (Get-WinEvent ...):\nTimeCreated  : 28/02/2026 04:30:56\nId           : 11\nProviderName : Microsoft-Windows-Security-Kerberos\nMessage      : Sample\n\nTimeCreated  : 27/02/2026 19:11:16\nId           : 10010\nProviderName : Microsoft-Windows-DistributedCOM\nMessage      : Sample")

	got := buildPersonalChatFallbackReply("explain me the error", nil, nil)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestBuildPersonalChatFallbackReply_GenericErrorExplainsFailureMemory(t *testing.T) {
	resetPersonalChatMemoryForTest()
	defer resetPersonalChatMemoryForTest()

	appendPersonalChatMemory("powershell: Get-CimInstance ...", "Command execution failed (Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature):\nGet-CimInstance : Access denied")

	got := buildPersonalChatFallbackReply("please explain the error", nil, nil)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestBuildPersonalChatFallbackReply_DiskUsageSuggestion(t *testing.T) {
	got := buildPersonalChatFallbackReply("how much disk space left in all drives", nil, nil)
	if got != "AI response is temporarily unavailable. Please try again in a moment." {
		t.Fatalf("expected unavailable fallback, got: %q", got)
	}
}

func TestGenerateAIChatResponse_OllamaNativeUsesNonStreamingPayload(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":{"content":"OLLAMA_NATIVE_OK"}}`))
	}))
	defer server.Close()

	cfg := config.AgentConfig{
		AIProvider:       "ollama",
		AIEndpoint:       server.URL + "/api/chat",
		AIModel:          "llama3.2:latest",
		AISystemPrompt:   "You are helpful.",
		AIRequestTimeout: 5 * time.Second,
		RequestTimeout:   5 * time.Second,
		CommandTimeout:   5 * time.Second,
	}

	got, err := generateAIChatResponse("say hi", cfg, nil, nil)
	if err != nil {
		t.Fatalf("generateAIChatResponse returned error: %v", err)
	}

	if got != "OLLAMA_NATIVE_OK" {
		t.Fatalf("unexpected response content: %q", got)
	}

	var payload struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(capturedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal captured request payload: %v", err)
	}

	if !strings.Contains(string(capturedBody), `"stream":false`) {
		t.Fatalf("expected stream=false in native payload, body=%s", string(capturedBody))
	}

	if payload.Stream {
		t.Fatalf("expected non-streaming ollama request")
	}
}
