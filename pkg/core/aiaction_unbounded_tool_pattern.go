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
// 2 番目のキャプチャが空なら、許可はコマンド本体で止まっており対象は限定されていない。
// 引数があれば（issue 番号、ブランチ名など）対象は限定されている。
var aiMutatingCommandPattern = regexp.MustCompile(
	`^(gh\s+(?:issue|pr|label|release|workflow|repo|run)\s+` +
		`(?:comment|edit|close|reopen|merge|delete|create|add|remove|transfer|lock)` +
		`|gh\s+api|git\s+push)(\s+.*)?$`)

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
		// Claude Code のワイルドカード表記 `:*` を取り除き、許可されている
		// プレフィックスそのものを得る。
		prefix := strings.TrimSuffix(strings.TrimSpace(entry[1]), ":*")
		prefix = strings.TrimSpace(prefix)

		match := aiMutatingCommandPattern.FindStringSubmatch(prefix)
		if match == nil {
			continue
		}

		// コマンド本体の後に引数があれば、対象は限定されている。
		if strings.TrimSpace(match[2]) != "" {
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
