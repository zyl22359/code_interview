package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"arithmetic/internal/converter"
	"arithmetic/internal/types"
)

func main() {
	// 读取题目文件
	questions, err := loadQuestions("题目.md")
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载题目失败：%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("加载了 %d 道题目\n", len(questions))

	// 创建转换器
	c := converter.NewConverter()

	// 批量转换
	answers := c.BatchConvert(questions)

	// 构建结果
	result := types.Result{
		PlayerName: "引擎研发中心 - 张三",
		PackageID:  "pkg-08e82c8d",
		Answers:    answers,
	}

	// 输出结果
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化结果失败：%v\n", err)
		os.Exit(1)
	}

	// 写入文件
	err = os.WriteFile("答案.json", output, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "写入文件失败：%v\n", err)
		os.Exit(1)
	}

	fmt.Println("答案已生成并保存到 答案.json")

	// 打印统计
	printStats(answers)
}

// loadQuestions 从 markdown 文件中加载题目
func loadQuestions(filename string) ([]types.Question, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	content := string(data)

	// 使用正则提取题号和自然语言输入
	idPattern := regexp.MustCompile(`"题号"\s*:\s*"([^"]+)"`)
	inputPattern := regexp.MustCompile(`"自然语言输入"\s*:\s*"([^"]+)"`)

	idMatches := idPattern.FindAllStringSubmatch(content, -1)
	inputMatches := inputPattern.FindAllStringSubmatch(content, -1)

	if len(idMatches) != len(inputMatches) {
		return nil, fmt.Errorf("题号和输入数量不匹配")
	}

	var questions []types.Question
	for i := range idMatches {
		questions = append(questions, types.Question{
			ID:    idMatches[i][1],
			Input: inputMatches[i][1],
		})
	}

	return questions, nil
}

// printStats 打印统计信息
func printStats(answers []types.Answer) {
	converted := 0
	unconvertible := 0
	empty := 0

	for _, a := range answers {
		switch {
		case a.Query == "":
			empty++
		case a.Query == "该需求不能直接转换为 FOFA 搜索语句":
			unconvertible++
		default:
			converted++
		}
	}

	fmt.Printf("\n统计:\n")
	fmt.Printf("  总题数：%d\n", len(answers))
	fmt.Printf("  已转换：%d\n", converted)
	fmt.Printf("  无法转换：%d\n", unconvertible)
	fmt.Printf("  待处理 (空)：%d\n", empty)
}
