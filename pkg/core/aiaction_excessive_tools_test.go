package core

import (
	"strings"
	"testing"
)

func TestAIActionExcessiveTools_DetectsBashWithIssuesTrigger(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) == 0 {
		t.Fatal("expected error for Bash tool with issues trigger, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "Bash") {
		t.Errorf("expected error description to contain \"Bash\", got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-excessive-tools" {
		t.Errorf("expected error type to be \"ai-action-excessive-tools\", got: %s", ruleErrors[0].Type)
	}
}

func TestAIActionExcessiveTools_AllowsReadOnlyTools(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Read,Glob,Grep"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) != 0 {
		t.Fatalf("expected no errors for read-only tools with issues trigger, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

func TestAIActionExcessiveTools_AllowsBashWithPushTrigger(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

	workflow := `
on:
  push:
    branches: [main]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash,Read,Write"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) != 0 {
		t.Fatalf("expected no errors for Bash tool with push trigger (trusted), got %d: %v", len(ruleErrors), ruleErrors)
	}
}

func TestAIActionExcessiveTools_PrivilegedTriggersTheSetOmitted(t *testing.T) {
	t.Parallel()

	// PrivilegedTriggers classifies these as attacker-controlled --
	// "Triggered by untrusted discussion comments" and "Review body is
	// attacker-controlled" -- but this rule's own trigger set omitted them, so a
	// workflow triggered only by one of these was not reported at all.
	for _, trigger := range []string{"discussion_comment", "pull_request_review"} {
		t.Run(trigger, func(t *testing.T) {
			t.Parallel()

			workflow := `
on:
  ` + trigger + `:
    types: [created]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash,Read,Write,Edit"
`
			parsed, errs := Parse([]byte(workflow))
			if len(errs) > 0 {
				t.Fatalf("failed to parse workflow: %v", errs)
			}
			rule := NewAIActionExcessiveToolsRule()
			v := NewSyntaxTreeVisitor()
			v.AddVisitor(rule)
			if err := v.VisitTree(parsed); err != nil {
				t.Fatalf("failed to visit tree: %v", err)
			}
			if len(rule.Errors()) == 0 {
				t.Fatalf("trigger %q was not treated as untrusted", trigger)
			}
		})
	}
}

func TestAIActionExcessiveTools_ClaudeCodeBaseActionIsCovered(t *testing.T) {
	t.Parallel()

	// claude-code-base-action is the lower-level action claude-code-action is
	// built on and takes the same claude_args input, but it was absent from
	// knownAIActionPrefixes -- so this exact configuration, found in a real
	// workflow with contents/issues/pull-requests write, was reported by no AI
	// rule at all.
	workflow := `
on:
  issues:
    types: [opened]
jobs:
  agent:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
    steps:
      - uses: anthropics/claude-code-base-action@v1
        with:
          claude_args: --allowedTools "Bash,Read,Write,Edit"
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}
	rule := NewAIActionExcessiveToolsRule()
	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}
	if len(rule.Errors()) == 0 {
		t.Fatal("claude-code-base-action granting Bash/Write/Edit was not reported")
	}
}

func TestKnownAIActionPrefix_DoesNotOvermatch(t *testing.T) {
	t.Parallel()

	// Adding claude-code-base-action must not make the boundary check looser:
	// an unrelated action whose name merely starts with a known one is still out.
	for _, uses := range []string{
		"anthropics/claude-code-action-malicious@v1",
		"openai/codex-action-fake@v1",
		"anthropics/claude-code-base-action-fork@v1",
		"evil/anthropics/claude-code-action@v1",
	} {
		if isKnownAIActionPrefix(uses) {
			t.Errorf("isKnownAIActionPrefix(%q) = true; want false", uses)
		}
	}
	for _, uses := range []string{
		"anthropics/claude-code-base-action@v1",
		"anthropics/claude-code-base-action/sub@v1",
		"anthropics/claude-code-action@v1",
	} {
		if !isKnownAIActionPrefix(uses) {
			t.Errorf("isKnownAIActionPrefix(%q) = false; want true", uses)
		}
	}
}
