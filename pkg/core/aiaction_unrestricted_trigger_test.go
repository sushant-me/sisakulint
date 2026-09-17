package core

import (
	"strings"
	"testing"
)

func runUnrestrictedTriggerRule(t *testing.T, workflow string) []*LintingError {
	t.Helper()

	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	rule := NewAIActionUnrestrictedTriggerRule()
	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	return rule.Errors()
}

func TestAIActionUnrestrictedTrigger_DetectsWildcard(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

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
          allowed_non_write_users: "*"
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
		t.Fatal("expected error for allowed_non_write_users: \"*\", got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "allowed_non_write_users") {
		t.Errorf("expected error description to contain \"allowed_non_write_users\", got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-unrestricted-trigger" {
		t.Errorf("expected error type to be \"ai-action-unrestricted-trigger\", got: %s", ruleErrors[0].Type)
	}
}

func TestAIActionUnrestrictedTrigger_IgnoresSafeConfig(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

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
		t.Fatalf("expected no errors for safe config, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

func TestAIActionUnrestrictedTrigger_IgnoresSimilarActionName(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

	// "openai/codex-action-malicious" should NOT match prefix "openai/codex-action"
	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action-malicious@v1
        with:
          allowed_non_write_users: "*"
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
		t.Fatalf("expected no errors for similar-but-different action name, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

func TestAIActionUnrestrictedTrigger_IgnoresNonAIAction(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          allowed_non_write_users: "*"
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
		t.Fatalf("expected no errors for non-AI action, got %d", len(ruleErrors))
	}
}

func TestAIActionUnrestrictedTrigger_StarAnywhereInTheList(t *testing.T) {
	t.Parallel()

	// The action definition: "Comma-separated list of usernames to allow without
	// write permissions, or '*' to allow all users." A list that *contains* '*'
	// therefore allows every user, but matching only the whole string missed it.
	for name, value := range map[string]string{
		"alone":                `"*"`,
		"single quoted":        `'*'`,
		"star then user":       `"*,some-trusted-user"`,
		"user then star":       `"some-trusted-user,*"`,
		"star with whitespace": `"* , some-trusted-user"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			workflow := `
on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ` + value + `
`
			result := runUnrestrictedTriggerRule(t, workflow)
			if len(result) == 0 {
				t.Fatalf("allowed_non_write_users: %s was not reported", value)
			}
		})
	}
}

func TestAIActionUnrestrictedTrigger_CodexActionInputName(t *testing.T) {
	t.Parallel()

	// openai/codex-action is in this rule's prefix list, but its equivalent input
	// is named `allow-users`, which the rule never read -- so a codex-action
	// workflow allowing every user was not reported at all.
	workflow := `
on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          allow-users: "*"
`
	if len(runUnrestrictedTriggerRule(t, workflow)) == 0 {
		t.Fatal("codex-action allow-users: \"*\" was not reported")
	}
}

func TestAIActionUnrestrictedTrigger_RestrictedValuesAreNotReported(t *testing.T) {
	t.Parallel()

	// Guarding the widening: an empty value is "allow nobody extra", not "allow
	// everyone", and a named list is the hardened form.
	for name, value := range map[string]string{
		"empty":        `""`,
		"named list":   `"alice,bob"`,
		"single named": `"alice"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			workflow := `
on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ` + value + `
`
			if result := runUnrestrictedTriggerRule(t, workflow); len(result) != 0 {
				t.Fatalf("allowed_non_write_users: %s was reported: %s", value, result[0].Description)
			}
		})
	}
}
