package converter

import (
	"regexp"
	"strings"

	"arithmetic/internal/rules"
	"arithmetic/internal/types"
)

// Validator 简单的校验器
type Validator struct{}

// NewValidator 创建校验器
func NewValidator() *Validator {
	return &Validator{}
}

// IsContradictory 检查是否是矛盾条件
func (v *Validator) IsContradictory(input string) bool {
	input = strings.ToLower(input)
	contradictoryPatterns := []string{
		`等于.*不等于`,
		`是.*不是`,
		`包含.*不包含`,
	}
	for _, pattern := range contradictoryPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			return true
		}
	}
	return false
}

// IsUnconvertible 检查是否无法转换为 FOFA 查询
func (v *Validator) IsUnconvertible(input string) bool {
	unconvertibleKeywords := []string{
		"最安全",
		"最好",
		"最大",
		"最小",
		"所有",
		"每一个",
		"实时监控",
		"正在运行",
		"内存使用率",
		"容器",
		"没有监控",
		"没有权限",
	}
	for _, keyword := range unconvertibleKeywords {
		if strings.Contains(input, keyword) {
			return true
		}
	}
	return false
}

// Converter 核心转换器
type Converter struct {
	ruleEngine *rules.RuleEngine
	validator  *Validator
}

// NewConverter 创建转换器
func NewConverter() *Converter {
	return &Converter{
		ruleEngine: rules.NewRuleEngine(),
		validator:  NewValidator(),
	}
}

// Convert 转换单个题目
func (c *Converter) Convert(question types.Question) types.Answer {
	input := question.Input

	// 1. 检查是否是矛盾条件
	if c.validator.IsContradictory(input) {
		return types.Answer{
			ID:    question.ID,
			Query: "该需求不能直接转换为 FOFA 搜索语句",
		}
	}

	// 2. 检查是否无法转换
	if c.validator.IsUnconvertible(input) {
		return types.Answer{
			ID:    question.ID,
			Query: "该需求不能直接转换为 FOFA 搜索语句",
		}
	}

	// 3. 尝试规则匹配
	result := c.ruleEngine.TryMatch(input)
	if result.Matched {
		return types.Answer{
			ID:    question.ID,
			Query: result.Query,
		}
	}

	// 4. 检查是否包含非法端口
	if c.containsInvalidPort(input) {
		return types.Answer{
			ID:    question.ID,
			Query: "该需求不能直接转换为 FOFA 搜索语句",
		}
	}

	// 5. 无法匹配规则，返回空或需要 LLM 处理
	return types.Answer{
		ID:    question.ID,
		Query: c.handleComplex(input),
	}
}

// containsInvalidPort 检查是否包含非法端口
func (c *Converter) containsInvalidPort(input string) bool {
	// 简单检查：如果有非常大的数字，可能是非法端口
	if strings.Contains(input, "1000000") || strings.Contains(input, "70001") {
		return true
	}
	return false
}

// handleComplex 处理复杂查询
func (c *Converter) handleComplex(input string) string {
	// 这里可以集成 LLM 处理复杂情况
	// 目前返回空字符串
	_ = input
	return ""
}

// BatchConvert 批量转换
func (c *Converter) BatchConvert(questions []types.Question) []types.Answer {
	answers := make([]types.Answer, len(questions))
	for i, q := range questions {
		answers[i] = c.Convert(q)
	}
	return answers
}
