package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// unsafeSandboxValues はサンドボックス保護を無効化する危険な safety-strategy の値。
//
// danger-full-access はここに含めない。codex-action が safety-strategy の値として
// 定義しているのは drop-sudo / read-only / unprivileged-user / unsafe の 4 つで、
// danger-full-access は別の入力（sandbox）の値である。到達しえない値を一覧に
// 残すと、その値が書かれたときに「危険な設定」と誤って報告してしまう。
var unsafeSandboxValues = []string{
	"unsafe",
}

// sandboxModeInputKeys は Codex のサンドボックスモードを選択する入力キー名。
//
// codex-action の `sandbox` 入力は「workspace-write、read-only、danger-full-access の
// いずれか」と定義されている。つまり danger-full-access はこの入力の値であり、
// safety-strategy の値ではない。safety-strategy だけを検査していたため、
// 実在しない組み合わせを検査し続ける一方で、実際に危険な設定を見落としていた。
var sandboxModeInputKeys = []string{
	"sandbox",
	"sandbox-mode",
	"sandbox_mode",
}

// unsafeSandboxModes はサンドボックスを無効化する sandbox 入力の値。
var unsafeSandboxModes = []string{
	"danger-full-access",
}

// sandboxStrategyInputKeys は safety-strategy を指定する入力キー名の候補。
// GitHub Actions の with セクションではハイフン区切りとアンダースコア区切りの両方が使われうる。
var sandboxStrategyInputKeys = []string{
	"safety-strategy",
	"safety_strategy",
}

// AIActionUnsafeSandboxRule は AI エージェントアクションの安全でないサンドボックス設定を検出するルール。
//
// 脆弱なパターン:
//
//	steps:
//	  - uses: openai/codex-action@v1
//	    with:
//	      safety-strategy: unsafe
//
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      claude_args: --dangerouslySkipPermissions
//
// OpenAI Codex セキュリティチェックリストでは safety-strategy に "drop-sudo"（デフォルト）、
// "unprivileged-user"、"read-only" を推奨し、"unsafe" や "danger-full-access" の使用を警告している。
// claude-code-action では --dangerouslySkipPermissions フラグが同等のサンドボックスバイパスに該当する。
//
// 安全なパターン:
//
//	steps:
//	  - uses: openai/codex-action@v1
//	    with:
//	      safety-strategy: drop-sudo
type AIActionUnsafeSandboxRule struct {
	BaseRule
}

// NewAIActionUnsafeSandboxRule は新しいルールインスタンスを返す。
func NewAIActionUnsafeSandboxRule() *AIActionUnsafeSandboxRule {
	return &AIActionUnsafeSandboxRule{
		BaseRule: BaseRule{
			RuleName: "ai-action-unsafe-sandbox",
			RuleDesc: "AI action has unsafe sandbox or safety-strategy configuration",
		},
	}
}

// VisitStep は各ステップを訪問し、AI エージェントアクションの安全でないサンドボックス設定を検出する。
func (r *AIActionUnsafeSandboxRule) VisitStep(node *ast.Step) error {
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

	r.checkSafetyStrategy(node, action)

	// `sandbox` は codex-action の入力である。他のアクションに書かれても
	// そのアクションは読まないため、危険な設定として報告してはならない。
	if aiIsCodexAction(action.Uses.Value) {
		r.checkSandboxMode(node, action)
	}
	r.checkDangerouslySkipPermissions(node, action)

	return nil
}

// aiIsCodexAction は uses が openai/codex-action を指すかを判定する。
// プレフィックスの直後が '@'、'/'、または文字列終端であることも確認し、
// "openai/codex-action-fork" のような別アクションを拾わない。
func aiIsCodexAction(uses string) bool {
	const prefix = "openai/codex-action"
	lower := strings.ToLower(strings.TrimSpace(uses))
	if !strings.HasPrefix(lower, prefix) {
		return false
	}
	rest := lower[len(prefix):]
	return rest == "" || rest[0] == '@' || rest[0] == '/'
}

// checkSafetyStrategy は safety-strategy 入力の値を検査する。
// safety-strategy が未設定の場合、デフォルト値は "drop-sudo"（安全）のため警告不要。
func (r *AIActionUnsafeSandboxRule) checkSafetyStrategy(node *ast.Step, action *ast.ExecAction) {
	for _, key := range sandboxStrategyInputKeys {
		input, exists := action.Inputs[key]
		if !exists || input == nil || input.Value == nil {
			continue
		}

		val := strings.TrimSpace(strings.ToLower(input.Value.Value))
		for _, unsafeVal := range unsafeSandboxValues {
			if val == unsafeVal {
				r.Errorf(
					node.Pos,
					`action %q has safety-strategy set to %q which disables sandbox protections. Use "drop-sudo", "unprivileged-user", or "read-only" instead.`,
					action.Uses.Value,
					input.Value.Value,
				)
				return
			}
		}
	}
}

// checkSandboxMode は sandbox 入力がサンドボックスを無効化していないか検査する。
func (r *AIActionUnsafeSandboxRule) checkSandboxMode(node *ast.Step, action *ast.ExecAction) {
	for _, key := range sandboxModeInputKeys {
		input, exists := action.Inputs[key]
		if !exists || input == nil || input.Value == nil {
			continue
		}

		val := strings.TrimSpace(strings.ToLower(input.Value.Value))
		for _, unsafeVal := range unsafeSandboxModes {
			if val == unsafeVal {
				r.Errorf(
					node.Pos,
					`action %q has %s set to %q which gives Codex unrestricted access to the runner. Use "workspace-write" or "read-only" instead.`,
					action.Uses.Value,
					key,
					input.Value.Value,
				)
				return
			}
		}
	}
}

// checkDangerouslySkipPermissions は claude_args に --dangerouslySkipPermissions が含まれているかを検査する。
func (r *AIActionUnsafeSandboxRule) checkDangerouslySkipPermissions(node *ast.Step, action *ast.ExecAction) {
	claudeArgsInput, exists := action.Inputs["claude_args"]
	if !exists || claudeArgsInput == nil || claudeArgsInput.Value == nil {
		return
	}

	if strings.Contains(claudeArgsInput.Value.Value, "--dangerouslySkipPermissions") {
		r.Errorf(
			node.Pos,
			`action %q uses --dangerouslySkipPermissions in claude_args which bypasses all permission checks. Remove this flag and configure specific tool permissions instead.`,
			action.Uses.Value,
		)
	}
}
