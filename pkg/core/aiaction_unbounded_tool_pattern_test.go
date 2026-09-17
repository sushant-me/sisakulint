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
		// The exact form names the refspec and nothing else. The `:*` form does
		// NOT bound it: `git push` takes several refspecs, so
		// `git push origin fix/issue-1 other-branch` also matches. See
		// TestAIActionUnboundedToolPattern_GitPushWildcardStillPermitsARefspec.
		"named branch, exact": "Read,Bash(git push origin fix/issue-1)",
		"label only":          "Read,Bash(gh issue edit 1234 --add-label:*)",
		"read only":           "Read,Glob,Grep,Bash(gh issue view:*)",
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

func TestAIActionUnboundedToolPattern_FlagOrRemoteAloneIsNotATarget(t *testing.T) {
	t.Parallel()

	// From review: "has an argument" is not "names a target".
	//
	//	git push origin          the argument is the *remote*; the refspec is
	//	                         still the agent's to choose
	//	gh api --method POST     the argument is a *flag*; the endpoint is open
	//	gh issue comment --body  the flag comes first, so no issue is named
	for name, allow := range map[string]string{
		"git push remote only": "Read,Bash(git push origin:*)",
		"gh api flag only":     "Read,Bash(gh api --method POST:*)",
		"gh issue flag first":  "Read,Bash(gh issue comment --body:*)",
		"no argument at all":   "Read,Bash(gh issue edit:*)",
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
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) == 0 {
				t.Fatalf("expected an error for %q, got none", allow)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_NamedTargetForTheSameCommandsIsAllowed(t *testing.T) {
	t.Parallel()

	// The other half of the test above: once the target is named, the same
	// commands are bounded and must not be reported.
	for name, allow := range map[string]string{
		// The `:*` sibling of this entry is NOT bounded - `git push` takes
		// several refspecs, so a further one can be appended. Only the exact
		// form names the target.
		"git push with ref": "Read,Bash(git push origin main)",
		// Exact form: the refspec is the whole command, so no other can follow.
		"git push with branch":     "Read,Bash(git push origin fix/issue-1)",
		"gh api with endpoint":     "Read,Bash(gh api repos/o/r/issues/1:*)",
		"gh issue with number":     "Read,Bash(gh issue comment 1234 --body:*)",
		"gh pr review with number": "Read,Bash(gh pr review 42 --approve:*)",
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
				t.Fatalf("expected no error for bounded pattern %q, got: %s", allow, ruleErrors[0].Description)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_DetectsPRReview(t *testing.T) {
	t.Parallel()

	// From review: `review` was missing from the verb enumeration, so
	// Bash(gh pr review:*) — which submits a review on any pull request — was
	// not reported.
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
          claude_args: --allowedTools "Read,Bash(gh pr review:*)"
`
	ruleErrors := runUnboundedToolPatternRule(t, workflow)

	if len(ruleErrors) == 0 {
		t.Fatal("expected an error for gh pr review, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "command(s) [gh pr review]") {
		t.Errorf("expected the reported list to be [gh pr review], got: %s", ruleErrors[0].Description)
	}
}

func TestAIActionUnboundedToolPattern_CoversTheMutatingSubcommands(t *testing.T) {
	t.Parallel()

	// The enumeration has to be complete, or a command that changes state slips
	// through by being absent from a list. This asserts the whole set, so adding
	// a subcommand to the pattern without intending to is visible.
	for _, verb := range []string{
		"comment", "edit", "close", "reopen", "merge", "delete", "create",
		"add", "remove", "transfer", "lock", "unlock", "pin", "unpin",
		"review", "ready", "clone", "upload",
	} {
		t.Run(verb, func(t *testing.T) {
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
          claude_args: --allowedTools "Read,Bash(gh pr ` + verb + `:*)"
`
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) == 0 {
				t.Fatalf("expected gh pr %s to be treated as mutating, got none", verb)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_ExactCommandWithoutWildcardIsNotUnbounded(t *testing.T) {
	t.Parallel()

	// Claude Code: "A rule with no `*` matches one exact command."
	// `Bash(git push)` therefore allows the bare command and no arguments, so it
	// cannot match an arbitrary ref; `Bash(git push:*)` can. Reporting the first
	// as "matches any target" is a false positive.
	for name, allow := range map[string]string{
		"exact git push":      "Read,Bash(git push)",
		"exact gh pr comment": "Read,Bash(gh pr comment)",
		"exact gh issue edit": "Read,Bash(gh issue edit)",
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
				t.Fatalf("exact command %q reported as unbounded: %s", allow, ruleErrors[0].Description)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_WildcardFormsAreStillReported(t *testing.T) {
	t.Parallel()

	// The two equivalent wildcard spellings must both still be findings.
	for name, allow := range map[string]string{
		"colon form": "Read,Bash(git push:*)",
		"space form": "Read,Bash(git push *)",
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
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) == 0 {
				t.Fatalf("wildcard form %q was not reported", allow)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_GroupWideGrantIsDetected(t *testing.T) {
	t.Parallel()

	// A grant naming a *group* rather than a subcommand authorises every verb in
	// that group, so `Bash(gh pr:*)` permits `gh pr merge`, `gh pr close` and
	// `gh pr edit`, and `Bash(git:*)` permits `git push`. These are broader than
	// the per-verb form the rule already caught, and were previously missed
	// entirely because a verb was required.
	for name, allow := range map[string]string{
		"all of gh":      "Read,Bash(gh:*)",
		"gh pr group":    "Read,Bash(gh pr:*)",
		"gh issue group": "Read,Bash(gh issue:*)",
		"all of git":     "Read,Bash(git:*)",
		"gh release":     "Read,Bash(gh release:*)",
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
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) == 0 {
				t.Fatalf("group-wide grant %q was not reported", allow)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_ReadOnlyGroupsAreNotReported(t *testing.T) {
	t.Parallel()

	// Widening detection to whole groups must not swallow read-only ones: a
	// hardened configuration still needs `gh search`, `gh pr view` and the like.
	for name, allow := range map[string]string{
		"gh search":     "Read,Bash(gh search:*)",
		"gh pr view":    "Read,Bash(gh pr view:*)",
		"gh pr diff":    "Read,Bash(gh pr diff:*)",
		"gh issue view": "Read,Bash(gh issue view:*)",
		"git log":       "Read,Bash(git log:*)",
		"git diff":      "Read,Bash(git diff:*)",
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
				t.Fatalf("read-only grant %q reported as unbounded: %s", allow, ruleErrors[0].Description)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_SpaceWildcardGroupFormsAreDetected(t *testing.T) {
	t.Parallel()

	// The reference states `Bash(ls:*)` and `Bash(ls *)` are the same rule, and
	// that `Bash(ls*)` is broader still. All three spellings must reach the same
	// verdict, otherwise a group-wide grant written with a space is invisible.
	for name, allow := range map[string]string{
		"git space":      "Read,Bash(git *)",
		"gh space":       "Read,Bash(gh *)",
		"gh pr space":    "Read,Bash(gh pr *)",
		"gh issue space": "Read,Bash(gh issue *)",
		"git nospace":    "Read,Bash(git*)",
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
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) == 0 {
				t.Fatalf("space-wildcard grant %q was not reported", allow)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_PrivilegedTriggersTheSetOmitted(t *testing.T) {
	t.Parallel()

	// This rule reuses aiExcessiveToolsUntrustedTriggers, so the same omission
	// applied here: a workflow triggered only by a review body or a discussion
	// comment was invisible.
	for name, trigger := range map[string]string{
		"review body":        "pull_request_review",
		"discussion comment": "discussion_comment",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			workflow := `
on:
  ` + trigger + `:
    types: [created]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Read,Bash(gh issue edit:*)"
`
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) == 0 {
				t.Fatalf("trigger %q was not treated as untrusted", trigger)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_GitPushWildcardStillPermitsARefspec(t *testing.T) {
	t.Parallel()

	// `git push` accepts several refspecs, so a pattern that names one and then
	// allows anything does not bound the target: it also matches
	// `git push origin main other-branch`, which pushes other-branch. Naming a
	// refspec in a `:*` pattern is therefore still an unbounded grant, and only
	// the exact form (no `*`) names a target. This is the case the docs used to
	// present as safe.
	for name, allow := range map[string]string{
		"named refspec + wildcard": "Read,Bash(git push origin main:*)",
		"option value then remote": "Read,Bash(git push -o ci.skip origin:*)",
		"remote only + wildcard":   "Read,Bash(git push origin:*)",
		"bare push + wildcard":     "Read,Bash(git push:*)",
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
			if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) == 0 {
				t.Fatalf("git push pattern %q was not reported", allow)
			}
		})
	}
}

func TestAIActionUnboundedToolPattern_GitPushExactFormIsBounded(t *testing.T) {
	t.Parallel()

	// The counterpart: with no wildcard the command is the whole grant, so no
	// additional refspec can be appended.
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
          claude_args: --allowedTools "Read,Bash(git push origin fix/issue-1)"
`
	if ruleErrors := runUnboundedToolPatternRule(t, workflow); len(ruleErrors) != 0 {
		t.Fatalf("exact git push was reported: %s", ruleErrors[0].Description)
	}
}
