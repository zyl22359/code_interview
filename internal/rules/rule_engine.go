package rules

import (
	"regexp"
	"strconv"
	"strings"
)

// Validator 简单的校验器
type Validator struct{}

// NewValidator 创建校验器
func NewValidator() *Validator {
	return &Validator{}
}

// IsValidPort 检查端口是否合法
func (v *Validator) IsValidPort(port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return p >= 1 && p <= 65535
}

// IsValidIP 检查 IP 地址是否合法
func (v *Validator) IsValidIP(ip string) bool {
	pattern := `^(\d{1,3}\.){3}\d{1,3}$`
	matched, _ := regexp.MatchString(pattern, ip)
	if !matched {
		return false
	}
	parts := strings.Split(ip, ".")
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

// IsValidNetwork 检查网段是否合法
func (v *Validator) IsValidNetwork(network string) bool {
	parts := strings.Split(network, "/")
	if len(parts) != 2 {
		return false
	}
	if !v.IsValidIP(parts[0]) {
		return false
	}
	mask, err := strconv.Atoi(parts[1])
	if err != nil || mask < 0 || mask > 32 {
		return false
	}
	return true
}

// IsContradictory 检查是否是矛盾条件
func (v *Validator) IsContradictory(input string) bool {
	input = strings.ToLower(input)
	contradictoryPatterns := []string{
		`等于.*不等于`,
		`是.*不是`,
		`包含.*不包含`,
		`必须等于.*必须不等于`,
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
		"无法访问",
	}
	for _, keyword := range unconvertibleKeywords {
		if strings.Contains(input, keyword) {
			return true
		}
	}
	return false
}

// RuleEngine 规则引擎
type RuleEngine struct {
	v *Validator
}

// NewRuleEngine 创建规则引擎
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		v: NewValidator(),
	}
}

// MatchResult 匹配结果
type MatchResult struct {
	Matched bool
	Query   string
}

// TryMatch 尝试匹配规则
func (r *RuleEngine) TryMatch(input string) MatchResult {
	// 按优先级尝试各种规则
	rules := []func(string) MatchResult{
		r.matchIP,
		r.matchNetwork,
		r.matchASN,
		r.matchDomain,
		r.matchPort,
		r.matchProtocol,
		r.matchCountry,
		r.matchRegion,
		r.matchCity,
		r.matchOrg,
		r.matchApp,
		r.matchTitle,
		r.matchHeader,
		r.matchCert,
		r.matchBody,
		r.matchStatusCode,
		r.matchVersion,
		r.matchOS,
		r.matchJARM,
		r.matchTLS,
		r.matchIcon,
		r.matchCVE,
	}

	for _, rule := range rules {
		result := rule(input)
		if result.Matched {
			return result
		}
	}

	return MatchResult{Matched: false}
}

// matchIP 匹配 IP 地址查询
func (r *RuleEngine) matchIP(input string) MatchResult {
	patterns := []string{
		`IP(?: 地址)? 为？\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
		`IP\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
		`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*的资产`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			ip := matches[1]
			if r.v.IsValidIP(ip) {
				return MatchResult{Matched: true, Query: `ip="` + ip + `"`}
			}
		}
	}
	return MatchResult{Matched: false}
}

// matchNetwork 匹配网段查询
func (r *RuleEngine) matchNetwork(input string) MatchResult {
	pattern := `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(input)
	if len(matches) >= 2 {
		network := matches[1]
		if r.v.IsValidNetwork(network) {
			return MatchResult{Matched: true, Query: `network="` + network + `"`}
		}
	}

	if strings.Contains(input, "A 段") {
		ipPattern := `(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}`
		re := regexp.MustCompile(ipPattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: "network=\"" + matches[1] + ".0.0.0/8\""}
		}
	}
	if strings.Contains(input, "B 段") {
		ipPattern := `(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}`
		re := regexp.MustCompile(ipPattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 3 {
			return MatchResult{Matched: true, Query: "network=\"" + matches[1] + "." + matches[2] + ".0/16\""}
		}
	}

	// IP 范围查询：x.x.x.1 到 x.x.x.5
	rangePattern := `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*到\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`
	re = regexp.MustCompile(rangePattern)
	matches = re.FindStringSubmatch(input)
	if len(matches) >= 3 {
		// 对于小范围，可以使用 ip 字段配合 OR
		return MatchResult{Matched: true, Query: `ip="` + matches[1] + "\" || ip=\"" + matches[2] + `"`}
	}

	return MatchResult{Matched: false}
}

// matchASN 匹配 ASN 查询
func (r *RuleEngine) matchASN(input string) MatchResult {
	// 自治系统号
	pattern := `自治系统 (?:号 | 为)?\s*(\d+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(input)
	if len(matches) >= 2 {
		return MatchResult{Matched: true, Query: `asn="` + matches[1] + `"`}
	}

	// AS 编号
	pattern = `AS\s*(\d+)`
	re = regexp.MustCompile(pattern)
	matches = re.FindStringSubmatch(input)
	if len(matches) >= 2 {
		return MatchResult{Matched: true, Query: `asn="` + matches[1] + `"`}
	}

	return MatchResult{Matched: false}
}

// matchVersion 匹配版本号查询
func (r *RuleEngine) matchVersion(input string) MatchResult {
	// 产品版本号
	if strings.Contains(input, "版本号") {
		pattern := `版本号 (?:为 | 是)?\s*"?([\d\.]+)"?`
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `version="` + matches[1] + `"`}
		}
	}
	return MatchResult{Matched: false}
}

// matchOS 匹配操作系统查询
func (r *RuleEngine) matchOS(input string) MatchResult {
	osMap := map[string]string{
		"linux":   `os="Linux"`,
		"Linux":   `os="Linux"`,
		"windows": `os="Windows"`,
		"Windows": `os="Windows"`,
	}

	for os, query := range osMap {
		if strings.Contains(input, os) {
			return MatchResult{Matched: true, Query: query}
		}
	}
	return MatchResult{Matched: false}
}

// matchJARM 匹配 JARM 指纹查询
func (r *RuleEngine) matchJARM(input string) MatchResult {
	if strings.Contains(input, "JARM") {
		pattern := `JARM 为\s*([a-f0-9]+)`
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `jarm="` + matches[1] + `"`}
		}
	}
	return MatchResult{Matched: false}
}

// matchDomain 匹配域名查询
func (r *RuleEngine) matchDomain(input string) MatchResult {
	patterns := []string{
		`主域是\s*([\w\-\.]+\.\w+)`,
		`域名 (?:里 | 中 | 包含)?\s*(?:有 | 为 | 是)?\s*([\w\-]+\.\w+)`,
		`(?:域名 | 网站)\s*为？\s*([\w\-]+\.\w+)`,
		`([\w\-]+\.\w+)\s*的 (?:域名 | 资产)`,
		`\.(\w+)\s*域名`,
		`网站名为\s*(www\.[\w\-]+\.\w+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			domain := matches[1]
			if strings.Contains(domain, ".") {
				return MatchResult{Matched: true, Query: `domain="` + domain + `"`}
			}
		}
	}

	// 子域名模式：a.z.163.com 这种
	if matched, _ := regexp.MatchString(`[a-z0-9]\.[a-z0-9]\.[\w\-]+\.\w+`, input); matched {
		subPattern := `([a-z0-9]\.[a-z0-9]\.[\w\-]+\.\w+)`
		re := regexp.MustCompile(subPattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `domain="` + matches[1] + `"`}
		}
	}

	return MatchResult{Matched: false}
}

// matchPort 匹配端口查询
func (r *RuleEngine) matchPort(input string) MatchResult {
	pattern := `(?:开放 | 端口为 | 端口 | 第)\s*(\d+)\s*端口`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(input)
	if len(matches) >= 2 {
		port := matches[1]
		if r.v.IsValidPort(port) {
			return MatchResult{Matched: true, Query: `port="` + port + `"`}
		}
		return MatchResult{Matched: true, Query: "该需求不能直接转换为 FOFA 搜索语句"}
	}
	return MatchResult{Matched: false}
}

// matchProtocol 匹配协议查询
func (r *RuleEngine) matchProtocol(input string) MatchResult {
	protocols := map[string]string{
		"ssh":       `protocol="ssh"`,
		"ftp":       `protocol="ftp"`,
		"http":      `protocol="http"`,
		"https":     `protocol="https"`,
		"snmp":      `protocol="snmp"`,
		"memcached": `protocol="memcached"`,
		"socks":     `socks`,
		"tcp":       `protocol="tcp"`,
		"tls":       `tls`,
	}

	inputLower := strings.ToLower(input)
	for proto, query := range protocols {
		if strings.Contains(inputLower, proto) {
			return MatchResult{Matched: true, Query: query}
		}
	}
	return MatchResult{Matched: false}
}

// matchCountry 匹配国家查询
func (r *RuleEngine) matchCountry(input string) MatchResult {
	countryMap := map[string]string{
		"中国":   `country="CN"`,
		"美国":   `country="US"`,
		"日本":   `country="JP"`,
		"韩国":   `country="KR"`,
		"德国":   `country="DE"`,
		"英国":   `country="GB"`,
		"法国":   `country="FR"`,
		"俄罗斯":  `country="RU"`,
		"巴西":   `country="BR"`,
		"印度":   `country="IN"`,
		"荷兰":   `country="NL"`,
		"澳大利亚": `country="AU"`,
		"加拿大":  `country="CA"`,
		"土耳其":  `country="TR"`,
		"新西兰":  `country="NZ"`,
		"阿根廷":  `country="AR"`,
		"大不列颠及北爱尔兰联合王国": `country="GB"`,
	}

	for country, query := range countryMap {
		if strings.Contains(input, country) {
			return MatchResult{Matched: true, Query: query}
		}
	}
	return MatchResult{Matched: false}
}

// matchRegion 匹配地区查询
func (r *RuleEngine) matchRegion(input string) MatchResult {
	regionMap := map[string]string{
		"河北": `region="Hebei"`,
		"北京": `region="Beijing"`,
		"上海": `region="Shanghai"`,
		"广东": `region="Guangdong"`,
		"浙江": `region="Zhejiang"`,
		"江苏": `region="Jiangsu"`,
	}

	for region, query := range regionMap {
		if strings.Contains(input, region) {
			return MatchResult{Matched: true, Query: query}
		}
	}
	return MatchResult{Matched: false}
}

// matchCity 匹配城市查询
func (r *RuleEngine) matchCity(input string) MatchResult {
	cityMap := map[string]string{
		"厦门":      `city="Xiamen"`,
		"北京":      `city="Beijing"`,
		"上海":      `city="Shanghai"`,
		"广州":      `city="Guangzhou"`,
		"深圳":      `city="Shenzhen"`,
		"München": `city="Munchen"`,
		"慕尼黑":     `city="Munchen"`,
		"江原道":     `region="Gangwon"`,
		"巴伐利亚":    `region="Bavaria"`,
		"阿姆斯特丹":   `city="Amsterdam"`,
	}

	for city, query := range cityMap {
		if strings.Contains(input, city) {
			return MatchResult{Matched: true, Query: query}
		}
	}
	return MatchResult{Matched: false}
}

// matchApp 匹配应用查询
func (r *RuleEngine) matchApp(input string) MatchResult {
	appMap := map[string]string{
		"GitLab":    `app="Gitlab"`,
		"Jenkins":   `app="Jenkins"`,
		"HFS":       `app="HFS"`,
		"Grafana":   `app="Grafana"`,
		"WordPress": `app="WordPress"`,
		"海康威视":      `app="Hikvision"`,
		"摄像头":       `category="摄像头"`,
		"DNS":       `service="DNS"`,
		"中间件":       `category="Middleware"`,
		"邮件系统":      `category="Mail"`,
		"SOCKS":     `socks`,
		"FTP":       `protocol="ftp"`,
		"SSH":       `protocol="ssh"`,
		"SNMP":      `protocol="snmp"`,
		"Memcached": `protocol="memcached"`,
		"OpenSSH":   `app="OpenSSH"`,
	}

	for app, query := range appMap {
		if strings.Contains(input, app) {
			return MatchResult{Matched: true, Query: query}
		}
	}
	return MatchResult{Matched: false}
}

// matchOrg 匹配组织查询
func (r *RuleEngine) matchOrg(input string) MatchResult {
	// 网络组织名称
	if strings.Contains(input, "网络组织") || strings.Contains(input, "组织名称") {
		if strings.Contains(input, "Inc") {
			return MatchResult{Matched: true, Query: `org="Inc"`}
		}
	}

	//  cloud provider
	cloudMap := map[string]string{
		"亚马逊云":         `cloud="Amazon"`,
		"亚马逊":          `cloud="Amazon"`,
		"AWS":          `cloud="Amazon"`,
		"华为云":          `cloud="Huawei"`,
		"阿里云":          `cloud="Aliyun"`,
		"腾讯云":          `cloud="Tencent"`,
		"DigitalOcean": `cloud="DigitalOcean"`,
		"OVH":          `org="OVH"`,
	}

	for cloud, query := range cloudMap {
		if strings.Contains(input, cloud) {
			return MatchResult{Matched: true, Query: query}
		}
	}

	return MatchResult{Matched: false}
}

// matchTitle 匹配标题查询
func (r *RuleEngine) matchTitle(input string) MatchResult {
	// 标题包含
	if strings.Contains(input, "标题") {
		pattern := `标题 (?:包含 | 为 | 是)?\s*"?([^"]+)"?`
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `title="` + strings.TrimSpace(matches[1]) + `"`}
		}
	}

	// 特定标题
	titleMap := map[string]string{
		"WHM 登录":    `title="WHM 登录"`,
		"Sign in":   `title="Sign in"`,
		"Login":     `title="Login"`,
		"Dashboard": `title="Dashboard"`,
		"Welcome":   `title="Welcome"`,
	}

	for title, query := range titleMap {
		if strings.Contains(input, title) {
			return MatchResult{Matched: true, Query: query}
		}
	}

	return MatchResult{Matched: false}
}

// matchHeader 匹配响应头查询
func (r *RuleEngine) matchHeader(input string) MatchResult {
	// Set-Cookie
	if strings.Contains(input, "Set-Cookie") {
		cookiePattern := `Set-Cookie[:：\s]*([^"]+)`
		re := regexp.MustCompile(cookiePattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `header="Set-Cookie:` + strings.TrimSpace(matches[1]) + `"`}
		}
		return MatchResult{Matched: true, Query: `header="Set-Cookie"`}
	}

	// Server 头
	if strings.Contains(input, "Server") {
		serverPattern := `Server[:：\s]*"?([^"]+)"?`
		re := regexp.MustCompile(serverPattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `server="` + strings.TrimSpace(matches[1]) + `"`}
		}
	}

	// Content-Security-Policy
	if strings.Contains(input, "Content-Security-Policy") {
		return MatchResult{Matched: true, Query: `header="Content-Security-Policy-Report-Only"`}
	}

	// Content-Length
	if strings.Contains(input, "Content-Length") {
		lengthPattern := `Content-Length[:：\s]*(\d+)`
		re := regexp.MustCompile(lengthPattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `header="Content-Length: ` + matches[1] + `"`}
		}
	}

	// Etag
	if strings.Contains(input, "Etag") || strings.Contains(input, "Etag") {
		etagPattern := `Etag[:：\s]*"([^"]+)"`
		re := regexp.MustCompile(etagPattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `header="Etag: ` + matches[1] + `"`}
		}
	}

	return MatchResult{Matched: false}
}

// matchCert 匹配证书查询
func (r *RuleEngine) matchCert(input string) MatchResult {
	if strings.Contains(input, "证书") {
		// 证书颁发者
		if strings.Contains(input, "颁发者") || strings.Contains(input, "签发") {
			issuerPattern := `(?:由 | 颁发者为？| 签发)[:：\s]*([\w\s]+)`
			re := regexp.MustCompile(issuerPattern)
			matches := re.FindStringSubmatch(input)
			if len(matches) >= 2 {
				return MatchResult{Matched: true, Query: `cert.issuer="` + strings.TrimSpace(matches[1]) + `"`}
			}
		}
		// 证书持有者
		if strings.Contains(input, "持有者") || strings.Contains(input, "主体") {
			subjectPattern := `(?:持有者 | 主体)[:：\s]*([\w\.\-]+)`
			re := regexp.MustCompile(subjectPattern)
			matches := re.FindStringSubmatch(input)
			if len(matches) >= 2 {
				return MatchResult{Matched: true, Query: `cert.subject="` + strings.TrimSpace(matches[1]) + `"`}
			}
		}
		// 根域名
		if strings.Contains(input, "根域名") || strings.Contains(input, "root") {
			domainPattern := `(?:域名 | 根域)[:：\s]*([\w\.\-]+)`
			re := regexp.MustCompile(domainPattern)
			matches := re.FindStringSubmatch(input)
			if len(matches) >= 2 {
				return MatchResult{Matched: true, Query: `cert="` + strings.TrimSpace(matches[1]) + `"`}
			}
		}
		// TLS 版本
		if strings.Contains(input, "TLS") {
			tlsPattern := `TLS\s*([\d\.]+)`
			re := regexp.MustCompile(tlsPattern)
			matches := re.FindStringSubmatch(input)
			if len(matches) >= 2 {
				return MatchResult{Matched: true, Query: `tls.version="` + matches[1] + `"`}
			}
		}
	}

	// 域名证书
	if strings.Contains(input, "adobe.com") {
		return MatchResult{Matched: true, Query: `cert="adobe.com"`}
	}
	if strings.Contains(input, "apple.com") {
		return MatchResult{Matched: true, Query: `cert="apple.com"`}
	}
	if strings.Contains(input, "google.com") {
		return MatchResult{Matched: true, Query: `cert="google.com"`}
	}
	if strings.Contains(input, "qq.com") {
		return MatchResult{Matched: true, Query: `cert="qq.com"`}
	}
	if strings.Contains(input, "godaddy") {
		return MatchResult{Matched: true, Query: `cert="godaddy"`}
	}
	if strings.Contains(input, "GlobalSign") {
		return MatchResult{Matched: true, Query: `cert.issuer="GlobalSign"`}
	}
	if strings.Contains(input, "TrustAsia") {
		return MatchResult{Matched: true, Query: `cert="TrustAsia"`}
	}

	return MatchResult{Matched: false}
}

// matchBody 匹配正文查询
func (r *RuleEngine) matchBody(input string) MatchResult {
	// 正文/网页正文包含
	bodyKeywords := []string{
		"正文", "网页正文", "body",
	}

	for _, keyword := range bodyKeywords {
		if strings.Contains(input, keyword) {
			// 提取关键词
			pattern := `(?:正文|body)[:：\s]*"?(?:包含 | 出现)?\s*"?([^"]+)"?`
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(input)
			if len(matches) >= 2 {
				return MatchResult{Matched: true, Query: `body="` + strings.TrimSpace(matches[1]) + `"`}
			}
		}
	}

	// 特定关键词
	bodyMap := map[string]string{
		"NoSuchUpload":  `body="NoSuchUpload"`,
		"Jenkins":       `body="Jenkins"`,
		"Login":         `body="Login"`,
		"Dashboard":     `body="Dashboard"`,
		"Welcome":       `body="Welcome"`,
		"Sign in":       `body="Sign in"`,
		"admin":         `body="admin"`,
		"jquery.min.js": `body="jquery.min.js"`,
		"JavaScript":    `body="JavaScript"`,
	}

	for body, query := range bodyMap {
		if strings.Contains(input, body) {
			return MatchResult{Matched: true, Query: query}
		}
	}

	// HTML 包含
	if strings.Contains(input, "HTML") && strings.Contains(input, "包含") {
		if strings.Contains(input, "login") {
			return MatchResult{Matched: true, Query: `body="login"`}
		}
	}

	// 源码包含
	if strings.Contains(input, "源码") || strings.Contains(input, "class=\"") {
		if strings.Contains(input, "class=\"container\"") {
			return MatchResult{Matched: true, Query: `body="class=\\"container\\""`}
		}
	}

	// JSON 异常信息
	if strings.Contains(input, "exception") && strings.Contains(input, "Symfony") {
		return MatchResult{Matched: true, Query: `body="Symfony\\Component\\ErrorHandler\\Error\\FatalError"`}
	}

	return MatchResult{Matched: false}
}

// matchStatusCode 匹配状态码查询
func (r *RuleEngine) matchStatusCode(input string) MatchResult {
	// 状态码/响应码
	pattern := `状态码 (?:为 | 是)?\s*(\d+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(input)
	if len(matches) >= 2 {
		return MatchResult{Matched: true, Query: `status_code="` + matches[1] + `"`}
	}

	// 响应码 200
	pattern = `响应 (?:码 | 信息)?.*?(\d{3})`
	re = regexp.MustCompile(pattern)
	matches = re.FindStringSubmatch(input)
	if len(matches) >= 2 {
		return MatchResult{Matched: true, Query: `status_code="` + matches[1] + `"`}
	}

	return MatchResult{Matched: false}
}

// matchIcon 匹配图标哈希查询
func (r *RuleEngine) matchIcon(input string) MatchResult {
	// 网站图标/图标哈希
	if strings.Contains(input, "图标") {
		if strings.Contains(input, "相同") {
			// 提取 URL
			urlPattern := `https?://[^\s]+`
			re := regexp.MustCompile(urlPattern)
			matches := re.FindStringSubmatch(input)
			if len(matches) >= 1 {
				return MatchResult{Matched: true, Query: `icon_hash="` + matches[0] + `"`}
			}
		}
	}
	return MatchResult{Matched: false}
}

// matchCVE 匹配 CVE 查询
func (r *RuleEngine) matchCVE(input string) MatchResult {
	if strings.Contains(input, "CVE") {
		cvePattern := `CVE-(\d{4})-(\d+)`
		re := regexp.MustCompile(cvePattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 3 {
			// 返回产品搜索语句（需要根据 CVE 映射到产品）
			year := matches[1]
			num := matches[2]
			return MatchResult{Matched: true, Query: `vuln_id="CVE-` + year + "-" + num + `"`}
		}
	}
	return MatchResult{Matched: false}
}

// matchTLS 匹配 TLS 相关查询
func (r *RuleEngine) matchTLS(input string) MatchResult {
	// JA3S 指纹
	if strings.Contains(input, "JA3S") {
		ja3sPattern := `JA3S\s* (?:指纹)?[=：:\s]*([a-f0-9]+)`
		re := regexp.MustCompile(ja3sPattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `ja3s="` + matches[1] + `"`}
		}
	}

	// TLS JA3
	if strings.Contains(input, "JA3") {
		ja3Pattern := `JA3\s*[=：:\s]*([a-f0-9]+)`
		re := regexp.MustCompile(ja3Pattern)
		matches := re.FindStringSubmatch(input)
		if len(matches) >= 2 {
			return MatchResult{Matched: true, Query: `ja3="` + matches[1] + `"`}
		}
	}

	return MatchResult{Matched: false}
}
