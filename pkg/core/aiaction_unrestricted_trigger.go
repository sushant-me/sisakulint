package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// knownAIActionPrefixes は検査対象の AI エージェントアクションのプレフィックスリスト
var knownAIActionPrefixes = []string{
	"anthropics/claude-code-action",
	// The lower-level action claude-code-action is built on. It takes the same
	// claude_args input, so every rule that reads claude_args applies to it
	// equally -- but it was absent from this list, so no AI rule saw it. Found
	// used in a real workflow with contents/issues/pull-requests write and
	// Bash/Write/Edit granted on an untrusted trigger.
	"anthropics/claude-code-base-action",
	"github/copilot-swe-agent",
	"openai/openai-actions",
	"openai/codex-action",
}

// AIActionUnrestrictedTriggerRule は allowed_non_write_users: "*" を検出するルール。
//
// 脆弱なパターン:
//
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      allowed_non_write_users: "*"
//
// このような設定では、すべての GitHub ユーザーが AI エージェントをトリガーできるため、
// Clinejection 攻撃（任意ユーザーが悪意のある指示を注入してエージェントを操作する攻撃）のリスクがある。
//
// 安全なパターン:
//
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      # allowed_non_write_users を省略するか、特定のユーザーを指定する
//	      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
type AIActionUnrestrictedTriggerRule struct {
	BaseRule
}

// NewAIActionUnrestrictedTriggerRule は新しいルールインスタンスを返す。
func NewAIActionUnrestrictedTriggerRule() *AIActionUnrestrictedTriggerRule {
	return &AIActionUnrestrictedTriggerRule{
		BaseRule: BaseRule{
			RuleName: "ai-action-unrestricted-trigger",
			RuleDesc: "AI action allows any GitHub user to trigger agent execution",
		},
	}
}

// VisitStep は各ステップを訪問し、AI エージェントアクションの unrestricted trigger 設定を検出する。
func (r *AIActionUnrestrictedTriggerRule) VisitStep(node *ast.Step) error {
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

	// 書き込み権限を持たない任意のユーザーを許可する入力名を検査する。
	//
	// claude-code-action: allowed_non_write_users
	// openai/codex-action: allow-users (別名であり、以前は検査していなかった)
	//
	// どちらも「カンマ区切りのユーザー名リスト、または '*' ですべてのユーザー」と
	// 定義されているため、リストの要素に '*' が含まれていれば全ユーザーが
	// トリガーできる。文字列全体が "*" である場合だけを見ると、
	// "*,some-trusted-user" のような指定を取り逃がす。
	for _, inputName := range aiUnrestrictedTriggerInputs {
		val, exists := action.Inputs[inputName]
		if !exists || val == nil || val.Value == nil {
			continue
		}

		if aiAllowsEveryUser(val.Value.Value) {
			r.Errorf(
				node.Pos,
				`action %q sets %s to allow every GitHub user to trigger AI agent execution. Restrict to specific users or organization members.`,
				action.Uses.Value,
				inputName,
			)
		}
	}

	return nil
}

// aiUnrestrictedTriggerInputs は「任意のユーザーを許可する」入力の名前。
// アクションごとに名前が異なるため、両方を検査する。
var aiUnrestrictedTriggerInputs = []string{
	"allowed_non_write_users", // anthropics/claude-code-action
	"allow-users",             // openai/codex-action
}

// aiAllowsEveryUser は、カンマ区切りの許可リストが全ユーザーを許可するかを判定する。
// 空文字列は「誰も追加で許可しない」であり、全ユーザー許可ではない。
func aiAllowsEveryUser(value string) bool {
	for _, entry := range strings.Split(value, ",") {
		if strings.TrimSpace(entry) == "*" {
			return true
		}
	}
	return false
}

// isKnownAIActionPrefix は uses の値が既知の AI アクションプレフィックスに一致するかを確認する。
// プレフィックスの直後が '@'、'/'、または文字列終端であることを確認し、
// "openai/codex-action-malicious@v1" のような誤検知を防ぐ。
func isKnownAIActionPrefix(uses string) bool {
	usesLower := strings.ToLower(uses)
	for _, prefix := range knownAIActionPrefixes {
		if strings.HasPrefix(usesLower, prefix) {
			// Exact match or followed by '@' or '/' (version or sub-path)
			if len(usesLower) == len(prefix) ||
				usesLower[len(prefix)] == '@' ||
				usesLower[len(prefix)] == '/' {
				return true
			}
		}
	}
	return false
}
