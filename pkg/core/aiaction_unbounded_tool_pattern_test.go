package core

import (
	"strings"
	"testing"
)

// runUnboundedToolPatternRule はワークフローを解析してルールを適用し、検出結果を返す。
func runUnboundedToolPatternRule(t *testing.T, workflow string) []*LintingError {
	t.Helper()

	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	rule := NewAIActionUnboundedToolPatternRule()
	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	return rule.Errors()
}

func TestAIActionUnboundedToolPattern_DetectsUnboundedIssueEdit(t *testing.T) {
	t.Parallel()

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
          claude_args: --allowedTools "Read,Bash(gh issue comment:*),Bash(gh issue edit:*)"
`
	ruleErrors := runUnboundedToolPatternRule(t, workflow)

	if len(ruleErrors) == 0 {
		t.Fatal("expected an error for an unbounded gh issue edit pattern, got none")
	}
	if ruleErrors[0].Type != "ai-action-unbounded-tool-pattern" {
		t.Errorf("expected error type to be \"ai-action-unbounded-tool-pattern\", got: %s", ruleErrors[0].Type)
	}
	for _, want := range []string{"gh issue comment", "gh issue edit"} {
		if !strings.Contains(ruleErrors[0].Description, want) {
			t.Errorf("expected description to contain %q, got: %s", want, ruleErrors[0].Description)
		}
	}
}

func TestAIActionUnboundedToolPattern_DetectsGitPushAndGhApi(t *testing.T) {
	t.Parallel()

	for name, allow := range map[string]string{
		"git push":    "Read,Bash(git push:*)",
		"gh api":      "Read,Bash(gh api:*)",
		"gh pr merge": "Read,Bash(gh pr merge:*)",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			workflow := `
on:
  issue_comment:
    types: [created]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "` + allow + `"
`
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) == 0 {
				t.Fatalf("expected an error for %q, got none", allow)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_AllowsBoundedPatterns(t *testing.T) {
	t.Parallel()

	// 対象を名指ししている許可は検出しない。ここが本ルールの要で、
	// ai-action-excessive-tools との差でもある。
	for name, allow := range map[string]string{
		"expression target": "Read,Bash(gh issue edit ${{ github.event.issue.number }}:*)",
		"literal target":    "Read,Bash(gh issue edit 1234:*)",
		"named branch":      "Read,Bash(git push origin fix/issue-1:*)",
		"label only":        "Read,Bash(gh issue edit 1234 --add-label:*)",
		"read only":         "Read,Glob,Grep,Bash(gh issue view:*)",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

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
          claude_args: --allowedTools "` + allow + `"
`
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) != 0 {
				t.Fatalf("expected no error for bounded pattern %q, got: %v", allow, ruleErrors[0].Description)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_AllowsOneTargetAmongMany(t *testing.T) {
	t.Parallel()

	// 1 つのエントリが限定されていても、同じ文字列に限定されていないエントリが
	// あれば検出する。混在は「片方だけ直した」状態なので見逃してはいけない。
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
          claude_args: --allowedTools "Read,Bash(gh issue edit 1234:*),Bash(git push:*)"
`
	ruleErrors := runUnboundedToolPatternRule(t, workflow)

	if len(ruleErrors) == 0 {
		t.Fatal("expected an error when one entry is unbounded, got none")
	}
	// The reported list must name only the unbounded entry. Checking the whole
	// message would pass vacuously: the advice text below the list contains
	// "gh issue edit" as the example of a bounded pattern.
	if !strings.Contains(ruleErrors[0].Description, "command(s) [git push]") {
		t.Errorf("expected the reported list to be exactly [git push], got: %s", ruleErrors[0].Description)
	}
}

func TestAIActionUnboundedToolPattern_RequiresUntrustedTrigger(t *testing.T) {
	t.Parallel()

	// メンテナだけが起動できるトリガーでは、攻撃者は対象を選べない。
	workflow := `
on:
  workflow_dispatch:
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Read,Bash(gh issue edit:*)"
`
	if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) != 0 {
		t.Fatalf("expected no error for a trusted trigger, got: %s", ruleErrors[0].Description)
	}
}

func TestAIActionUnboundedToolPattern_IgnoresNonAIActions(t *testing.T) {
	t.Parallel()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          claude_args: --allowedTools "Bash(gh issue edit:*)"
`
	if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) != 0 {
		t.Fatalf("expected no error for a non-AI action, got: %s", ruleErrors[0].Description)
	}
}

func TestAIActionUnboundedToolPattern_ReportsEachCommandOnce(t *testing.T) {
	t.Parallel()

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
          claude_args: --allowedTools "Bash(gh issue comment:*),Bash(gh issue comment:*)"
`
	ruleErrors := runUnboundedToolPatternRule(t, workflow)

	if len(ruleErrors) != 1 {
		t.Fatalf("expected exactly one error, got %d", len(ruleErrors))
	}
	if n := strings.Count(ruleErrors[0].Description, "gh issue comment"); n != 1 {
		t.Errorf("expected the command to be reported once, got %d", n)
	}
}
