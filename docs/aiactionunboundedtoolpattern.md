---
title: "AI Action Unbounded Tool Pattern Rule"
weight: 1
---

### AI Action Unbounded Tool Pattern Rule Overview

This rule detects **AI agent actions granted a mutating command that matches any
target**, in workflows triggered by untrusted events such as `issues`,
`issue_comment`, `discussion`, `pull_request_target`, and `workflow_run`.

It complements [AI Action Excessive Tools]({{< ref "aiactionexcessivetools.md" >}}).
That rule catches a tool granted **without restriction** (`Bash`, `Write`,
`Edit`). This rule catches the narrower-looking form that is still unbounded:

```yaml
claude_args: --allowedTools "Read,Bash(gh issue edit:*)"   # any issue
claude_args: --allowedTools "Read,Bash(git push:*)"        # any ref
```

**Affected Actions:**
- `anthropics/claude-code-action`
- `github/copilot-swe-agent`
- `openai/openai-actions`
- `openai/codex-action`

### Security Impact

**Severity: High**

A `Bash(...)` entry in `--allowedTools` is a **command prefix**, and the grant
ends at Claude Code's `:*` wildcard. Whatever precedes the wildcard is what the
grant is scoped to, which gives three distinguishable forms:

| Pattern | What the agent may act on |
|---|---|
| `Bash(gh issue edit:*)` | any issue in the repository |
| `Bash(gh issue edit 1234:*)` | issue 1234 only |
| `Bash(gh issue edit ${{ github.event.issue.number }}:*)` | the triggering issue only |

The first form is the finding. The workflow's prompt usually *says* to work on the
issue that triggered the run, and the agent usually does — but the **permission**
is not scoped to it. A successful prompt injection can therefore name a different
issue or ref, and the permission will allow it. The prompt is a request; the
pattern is the bound.

The impact is bounded by the grant: `gh issue edit` can modify or close issues
the agent was never asked to touch, while `git push` or `gh api` reach the
repository itself.

### Vulnerable Example

```yaml
name: Issue Triage
on:
  issues:
    types: [opened]        # any GitHub user can open an issue

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          # The agent may edit ANY issue, not just the one that triggered it.
          claude_args: --allowedTools "Read,Bash(gh issue comment:*),Bash(gh issue edit:*)"
```

### Detection Output

```bash
vulnerable.yaml:12:9: action "anthropics/claude-code-action@v1" grants unbounded mutating command(s) [gh issue comment, gh issue edit] via claude_args in a workflow triggered by untrusted events. A pattern ending at the command (for example "gh issue edit:*") matches any target, so a successful prompt injection can act on issues or refs the attacker chooses rather than the one that triggered the run. Name the target in the pattern instead, for example "gh issue edit ${{ github.event.issue.number }}:*". Note that this is a prefix match on a command string, not a parse. [ai-action-unbounded-tool-pattern]
     12 |       - uses: anthropics/claude-code-action@v1
```

### Security Background

#### Mutating commands covered

A command is treated as mutating when it can change the repository's state:

| Command | Reaches |
|---|---|
| `gh issue edit` / `close` / `reopen` | any issue |
| `gh issue comment` | any issue or pull request |
| `gh pr edit` / `close` / `merge` / `review` | any pull request |
| `gh label` / `gh release` / `gh workflow run` / `gh repo edit` | repository metadata |
| `gh api` | any REST endpoint the token allows |
| `git push` | any ref the token allows |

Read commands (`gh issue view`, `gh pr diff`, `gh search`, `git log`) are not
reported: they are what a hardened configuration still needs.

#### Why the distinction matters

This is the difference between a mitigation and its absence in a workflow whose
permissions block is otherwise identical. Two workflows can both grant
`issues: write` and both run on `issues: opened`:

- one names the target in the tool pattern, so a steered agent cannot be
  redirected;
- the other matches any argument, so it can.

Nothing in the `permissions:` block distinguishes them, and no prompt wording
does either.

### Detection Logic

The rule performs two-phase detection:

1. **Workflow-level**: identifies whether any `on:` trigger is in the untrusted
   trigger list, shared with [AI Action Excessive Tools]({{< ref "aiactionexcessivetools.md" >}})
   so the two rules cannot disagree about what "untrusted" means.
2. **Step-level**: extracts each `Bash(...)` entry from `claude_args`, strips the
   trailing `:*` wildcard to obtain the permitted prefix, and reports the entry
   when the prefix stops at a mutating command with no argument after it.

An entry that names an argument — a literal number, a branch, or an expression
such as `${{ github.event.issue.number }}` — is not reported.

### Remediation Steps

1. **Name the target in the pattern.** This is usually a one-line change and it
   removes none of the agent's useful capability:

   ```yaml
   # before
   claude_args: --allowedTools "Read,Bash(gh issue edit:*),Bash(gh issue comment:*)"

   # after
   claude_args: --allowedTools "Read,Bash(gh issue edit ${{ github.event.issue.number }}:*),Bash(gh issue comment ${{ github.event.issue.number }}:*)"
   ```

2. **Scope the push to its branch**, if the workflow pushes a fix:

   ```yaml
   claude_args: --allowedTools "Read,Bash(git push origin fix/issue-${{ github.event.issue.number }}:*)"
   ```

3. **Take the target out of the model's reach entirely.** Have the agent write
   its output to a file and let a later, non-agent step post it with the target
   taken from the event:

   ```yaml
   - uses: anthropics/claude-code-action@v1
     with:
       claude_args: --allowedTools "Read,Write,Glob,Grep,Bash(gh issue view:*)"
       prompt: Write your comment to /tmp/comment.md

   - name: Post the agent's comment
     env:
       ISSUE: ${{ github.event.issue.number }}
       REPO: ${{ github.repository }}
     run: gh issue comment "$ISSUE" --repo "$REPO" --body-file /tmp/comment.md
   ```

4. **Drop `gh api` and bare `git push`** from untrusted-trigger workflows. Both
   are unbounded by construction and cannot be scoped by a prefix.

### Safe vs. Unsafe Patterns

#### Unsafe Patterns (Flagged)

```yaml
claude_args: --allowedTools "Read,Bash(gh issue edit:*)"
claude_args: --allowedTools "Read,Bash(gh issue comment:*),Bash(gh pr comment:*)"
claude_args: --allowedTools "Read,Bash(git push:*)"
claude_args: --allowedTools "Read,Bash(gh api:*)"
```

#### Safe Patterns (Not Flagged)

```yaml
# target named by expression
claude_args: --allowedTools "Read,Bash(gh issue edit ${{ github.event.issue.number }}:*)"

# target named literally
claude_args: --allowedTools "Read,Bash(gh issue edit 1234:*)"

# branch named
claude_args: --allowedTools "Read,Bash(git push origin fix/issue-1:*)"

# read-only
claude_args: --allowedTools "Read,Glob,Grep,Bash(gh issue view:*)"

# trusted trigger: the attacker cannot choose the target
on:
  workflow_dispatch:
steps:
  - uses: anthropics/claude-code-action@v1
    with:
      claude_args: --allowedTools "Read,Bash(gh issue edit:*)"
```

### Best Practices

1. **Treat the tool pattern as the security boundary, and the prompt as intent.**
   Instructions in a prompt are input; a prefix in an allowlist is a bound.

2. **Scope by the event, not by a constant.** `${{ github.event.issue.number }}`
   is the value the attacker already controls, so naming it costs nothing and
   removes their choice.

3. **Prefer a later, non-agent step for anything privileged.** The agent writes a
   file; a step outside the model's reach posts it.

4. **Remember it is a prefix, not a parse.** Scoping raises the cost of
   redirection; it does not make it impossible. Where that matters, use the
   separate-step form above.

### Complementary Rules

- [AI Action Excessive Tools]({{< ref "aiactionexcessivetools.md" >}}): detects
  tools granted without restriction (`Bash`, `Write`, `Edit`)
- [AI Action Unrestricted Trigger]({{< ref "aiactionunrestrictedtrigger.md" >}}):
  detects open access (`allowed_non_write_users: "*"`)
- [AI Action Prompt Injection]({{< ref "aiactionpromptinjection.md" >}}): detects
  untrusted input interpolated into a prompt
- [AI Action Execution Order]({{< ref "aiactionexecutionorder.md" >}}): detects
  an agent action that is not the last step in its job

### References

- [Anthropic: claude-code-action](https://github.com/anthropics/claude-code-action)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [GitHub: Events that trigger workflows](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows)
- [CWE-1427: Improper Neutralization of Input Used for LLM Prompting](https://cwe.mitre.org/data/definitions/1427.html)
