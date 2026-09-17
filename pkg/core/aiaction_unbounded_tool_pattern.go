package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// aiBashToolEntryPattern は --allowedTools の中の `Bash(...)` エントリを抽出する。
//
// Claude Code の --allowedTools はコマンドの「前方一致プレフィックス」を許可する。
// 許可の終端は `:*` ワイルドカードなので、ワイルドカードの直前までが権限の範囲になる。
//
//	Bash(gh issue edit:*)             -> 任意の issue を編集できる
//	Bash(gh issue edit 1234:*)        -> その issue だけ
//	Bash(gh issue edit ${{ ... }}:*)  -> その入力だけ
//
// 1 行目は攻撃者が対象を選べるため、プロンプトインジェクションが成功すると
// トリガーした issue 以外も操作できてしまう。
var aiBashToolEntryPattern = regexp.MustCompile(`Bash\(([^)]*)\)`)

// aiMutatingCommandPattern はリポジトリを変更するコマンドを
// 「コマンド本体」と「それに続く引数」に分解する。
//
// 対象が限定されているかどうかは、コマンド種別ごとに aiTargetIsBounded が判断する。
// 引数が「ある」ことだけでは限定にならない:
//
//	git push origin:*      -> origin はリモートであり、ref は指定されていない
//	gh api --method POST:* -> --method はフラグであり、endpoint は指定されていない
var aiMutatingCommandPattern = regexp.MustCompile(
	`^(gh\s+(?:issue|pr|label|release|workflow|repo|run)\s+` +
		`(?:comment|edit|close|reopen|merge|delete|create|add|remove|transfer|` +
		`lock|unlock|pin|unpin|review|ready|clone|upload)` +
		`|gh\s+api|git\s+push)(\s+.*)?$`)

// aiMutatingGroupPattern は、サブコマンドではなくグループ全体を許可する
// プレフィックスに一致する。
//
//	gh pr:*    -> gh pr merge / close / edit / review をまとめて許可する
//	gh:*       -> gh のすべてのサブコマンドを許可する
//	git:*      -> git push を含むすべての git コマンドを許可する
//
// これらは個別の動詞を名指しした許可より広い。動詞を要求する
// aiMutatingCommandPattern では拾えないため、別に判定する。
// `gh search:*` や `gh pr view:*` のような読み取り専用のものは含めない。
var aiMutatingGroupPattern = regexp.MustCompile(
	`^(gh(?:\s+(?:issue|pr|label|release|workflow|repo|run))?|git)$`)

// aiTargetIsBounded は、許可プレフィックスが対象を名指ししているかを判定する。
//
// 引数の有無だけでは決まらない。コマンドごとに「対象」が何番目のトークンかを
// 知る必要がある:
//
//	gh issue edit 1234           先頭が対象        -> 限定
//	gh issue comment --body x    先頭がフラグ      -> 限定されていない（issue は任意）
//	gh api repos/o/r/issues/1    endpoint が先頭   -> 限定
//	gh api --method POST         先頭がフラグ      -> 限定されていない（endpoint は任意）
//	git push origin main         リモート + ref    -> 限定
//	git push origin              リモートのみ      -> 限定されていない（ref は任意）
func aiTargetIsBounded(command, rest string) bool {
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		// 引数がまったく無い場合は、必ず対象が残っている。
		return false
	}

	if strings.HasPrefix(command, "git push") {
		// refspec が名指しされていなければ、エージェントは任意の ref を push できる。
		// リモートだけの指定（git push origin）は限定にならない。
		positional := 0
		for _, field := range fields {
			if !strings.HasPrefix(field, "-") {
				positional++
			}
		}
		return positional >= 2
	}

	// gh のコマンドは `gh <group> <verb> <target> [flags]` の形で、
	// `gh api` も endpoint が先頭に来る。先頭がフラグなら、対象は名指しされていない。
	return !strings.HasPrefix(fields[0], "-")
}

// AIActionUnboundedToolPatternRule は、信頼されていないトリガーのワークフローで
// AI エージェントに「対象を限定しない」変更コマンドを許可しているパターンを検出するルール。
//
// ai-action-excessive-tools は `Bash`（引数なし＝無制限のシェル）のような
// ツール名そのものを検出する。本ルールはその補完で、
// `Bash(<コマンド>:*)` という一見制限された形の許可を対象にする。
//
// 脆弱なパターン:
//
//	on:
//	  issues:
//	    types: [opened]
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      claude_args: --allowedTools "Read,Bash(gh issue comment:*),Bash(gh issue edit:*)"
//
// エージェントは「トリガーされた issue にコメントする」つもりで許可されているが、
// 実際にはどの issue にもコメント・編集できてしまう。
// issues / issue_comment トリガーは任意の GitHub ユーザーが発生させられるため、
// 攻撃者が対象を指定できる状態になる。
//
// 安全なパターン:
//
//	claude_args: --allowedTools "Read,Bash(gh issue comment ${{ github.event.issue.number }}:*)"
//
// 許可プレフィックスが対象を名指ししているため、別の issue へは向けられない。
type AIActionUnboundedToolPatternRule struct {
	BaseRule
	hasUntrustedTrigger bool
}

// NewAIActionUnboundedToolPatternRule は新しいルールインスタンスを返す。
func NewAIActionUnboundedToolPatternRule() *AIActionUnboundedToolPatternRule {
	return &AIActionUnboundedToolPatternRule{
		BaseRule: BaseRule{
			RuleName: "ai-action-unbounded-tool-pattern",
			RuleDesc: "AI action grants a mutating command pattern that matches any target in a workflow triggered by untrusted users",
		},
	}
}

// VisitWorkflowPre はワークフローを訪問し、信頼されていないトリガーを収集する。
func (r *AIActionUnboundedToolPatternRule) VisitWorkflowPre(node *ast.Workflow) error {
	r.hasUntrustedTrigger = false

	for _, event := range node.On {
		webhookEvent, ok := event.(*ast.WebhookEvent)
		if !ok {
			continue
		}
		// トリガー集合は ai-action-excessive-tools と同じ定義を使う。
		// 「任意の GitHub ユーザーが発生させられるイベント」という概念が同一なので、
		// 二重に定義すると片方だけ更新されて食い違う。
		if aiExcessiveToolsUntrustedTriggers[webhookEvent.EventName()] {
			r.hasUntrustedTrigger = true
			r.Debug("Detected untrusted trigger: %s", webhookEvent.EventName())
			break
		}
	}

	return nil
}

// VisitStep は各ステップを訪問し、対象を限定しない変更コマンドの許可を検出する。
func (r *AIActionUnboundedToolPatternRule) VisitStep(node *ast.Step) error {
	if !r.hasUntrustedTrigger {
		return nil
	}

	action, ok := node.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	if action.Uses == nil {
		return nil
	}

	if !isKnownAIActionPrefix(action.Uses.Value) {
		return nil
	}

	claudeArgsInput, exists := action.Inputs["claude_args"]
	if !exists || claudeArgsInput == nil || claudeArgsInput.Value == nil {
		return nil
	}

	found := findUnboundedMutatingCommands(claudeArgsInput.Value.Value)
	if len(found) == 0 {
		return nil
	}

	r.Errorf(
		node.Pos,
		`action %q grants unbounded mutating command(s) [%s] via claude_args in a workflow triggered by untrusted events. A pattern ending at the command (for example "gh issue edit:*") matches any target, so a successful prompt injection can act on issues or refs the attacker chooses rather than the one that triggered the run. Name the target in the pattern instead, for example "gh issue edit ${{ github.event.issue.number }}:*". Note that this is a prefix match on a command string, not a parse.`,
		action.Uses.Value,
		strings.Join(found, ", "),
	)

	return nil
}

// findUnboundedMutatingCommands は claude_args から、対象を限定していない
// 変更コマンドを重複なく抽出して返す。
func findUnboundedMutatingCommands(claudeArgs string) []string {
	var found []string
	seen := make(map[string]bool)

	for _, entry := range aiBashToolEntryPattern.FindAllStringSubmatch(claudeArgs, -1) {
		raw := strings.TrimSpace(entry[1])

		// `*` を含まないルールは 1 つの完全一致コマンドにしか一致しない
		// (Claude Code のドキュメント: "A rule with no `*` matches one exact
		// command")。`Bash(git push)` が許可するのは引数なしの `git push` だけで、
		// 任意の ref を許可するのは `Bash(git push:*)` の方である。
		// これは「任意の対象に一致する許可」ではないので報告しない。
		if !strings.Contains(raw, "*") {
			continue
		}

		// ワイルドカード表記を取り除き、許可されているプレフィックスそのものを得る。
		// Claude Code のドキュメントでは `Bash(ls:*)` と `Bash(ls *)` は同じ規則で
		// あり、`Bash(ls*)` はさらに広い（`lsof` にも一致する）。
		// 3 つとも同じプレフィックスとして扱う。
		prefix := raw
		for _, suffix := range []string{":*", " *", "*"} {
			if strings.HasSuffix(prefix, suffix) {
				prefix = strings.TrimSuffix(prefix, suffix)
				break
			}
		}
		prefix = strings.TrimSpace(prefix)

		// グループ全体の許可は、動詞を名指ししていなくても変更系を含む。
		if g := aiMutatingGroupPattern.FindStringSubmatch(prefix); g != nil {
			if !seen[g[1]] {
				seen[g[1]] = true
				found = append(found, g[1])
			}
			continue
		}

		match := aiMutatingCommandPattern.FindStringSubmatch(prefix)
		if match == nil {
			continue
		}

		// 対象が名指しされていれば、その許可は限定されている。
		if aiTargetIsBounded(strings.Join(strings.Fields(match[1]), " "), match[2]) {
			continue
		}

		command := strings.Join(strings.Fields(match[1]), " ")
		if !seen[command] {
			seen[command] = true
			found = append(found, command)
		}
	}

	return found
}
