package types

// Question 题目结构
type Question struct {
	ID    string `json:"题号"`
	Input string `json:"自然语言输入"`
}

// Answer 答案结构
type Answer struct {
	ID    string `json:"题号"`
	Query string `json:"查询语句"`
}

// Result 结果结构
type Result struct {
	PlayerName string   `json:"选手名称"`
	PackageID  string   `json:"参赛包编号"`
	Answers    []Answer `json:"答案"`
}
