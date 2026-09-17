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
	for _, inputName := range aiUnrestrictedTriggerInputsFor(action.Uses.Value) {
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

// aiUnrestrictedTriggerInputs は、アクションごとに「任意のユーザーを許可する」
// 入力の名前を対応づける。名前が違うだけでなく、入力を持たないアクションも
// あるため、一覧ではなく対応表にしている。
//
// すべて action.yml で確認した事実にもとづく:
//
//	anthropics/claude-code-action      allowed_non_write_users, allowed_bots
//	anthropics/claude-code-base-action なし
//	openai/codex-action                allow-users, allow-bots
//
// 以前は両方の名前をすべてのアクションに対して検査していた。そのため
// 入力を持たない claude-code-base-action に allowed_non_write_users が
// 書かれていても報告してしまい、実際には誰も許可されていない設定を
// 「全ユーザーが実行できる」と誤って伝えていた。
//
// 対応表にないアクション（github/copilot-swe-agent、openai/openai-actions）は
// action.yml を取得して確認できていないため、推測せず何も報告しない。
// 誤検知を避ける側に倒した判断であり、確認でき次第ここに追加する。
var aiUnrestrictedTriggerInputs = map[string][]string{
	"anthropics/claude-code-action":      {"allowed_non_write_users"},
	"anthropics/claude-code-base-action": {},
	"openai/codex-action":                {"allow-users"},
}

// aiUnrestrictedTriggerInputsFor は uses に対応する入力名を返す。
// 未知のアクションには nil を返し、呼び出し側は何も報告しない。
func aiUnrestrictedTriggerInputsFor(uses string) []string {
	lower := strings.ToLower(strings.TrimSpace(uses))
	for prefix, names := range aiUnrestrictedTriggerInputs {
		if strings.HasPrefix(lower, prefix) {
			rest := lower[len(prefix):]
			// プレフィックスの直後が '@'、'/'、または文字列終端であることを
			// 確認し、"openai/codex-action-x" のような別アクションを拾わない。
			if rest == "" || rest[0] == '@' || rest[0] == '/' {
				return names
			}
		}
	}
	return nil
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
