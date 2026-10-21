package libmihomo

// Start-path robustness: a panic anywhere in config parsing must not take the extension down (the user
// would only see "连接中…" then nothing), and the core's English errors get a Chinese reason first.

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
)

// safeApply runs apply and turns a panic into an error (logged with a short stack in the stage log).
func safeApply(home, configPath string, fd int32) (err error) {
	defer func() {
		if p := recover(); p != nil {
			st := string(debug.Stack())
			if len(st) > 1500 {
				st = st[:1500]
			}
			stage("PANIC in core apply: %v\n%s", p, st)
			err = fmt.Errorf("内核内部错误（已拦截，扩展没有崩溃）：%v。可在 诊断 → 导出诊断包 后反馈；也可以试试安全模式", p)
		}
	}()
	return apply(home, configPath, fd)
}

type errHint struct {
	re   *regexp.Regexp
	hint string
}

// errHints maps common mihomo parse / start errors to a Chinese reason. The original text follows it.
var errHints = []errHint{
	{regexp.MustCompile(`(?i)yaml:|unmarshal|mapping values are not allowed|did not find expected`), "配置文件格式错误（YAML）"},
	{regexp.MustCompile(`(?i)(rule[- ]?provider|ruleset|rule set)`), "规则集加载失败"},
	{regexp.MustCompile(`(?i)(proxy[- ]?provider)`), "节点集（proxy-provider）加载失败"},
	{regexp.MustCompile(`(?i)(geosite|geoip|mmdb|metadb|asn\.mmdb|geodata).*(download|not found|no such file|invalid|failed)|(download|can't download).*(geo|mmdb)`), "地理数据库缺失或损坏，且下载失败（可在 更多 → 高级设置 → 地理数据库 更新，或打开国内镜像）"},
	{regexp.MustCompile(`(?i)(proxy group|proxy-group|group).*(not found|doesn't exist|does not exist)|'proxies' missing|use or proxies missing`), "策略组引用了不存在的节点或策略组"},
	{regexp.MustCompile(`(?i)(proxy|proxies) ?\d*:.*(missing|invalid|unsupported|not support)|parse proxy|unsupport proxy type`), "有节点无法解析（协议参数缺失或不支持）"},
	{regexp.MustCompile(`(?i)rules\[\d+\]|rule .*(invalid|not found|unsupported)|payload`), "规则写法有误或引用了不存在的策略"},
	{regexp.MustCompile(`(?i)address already in use|bind:`), "本地端口被占用（仅代理模式 / 局域网共享的端口或控制器端口）"},
	{regexp.MustCompile(`(?i)tun|file-descriptor|gvisor`), "隧道初始化失败"},
	{regexp.MustCompile(`(?i)dns|nameserver`), "DNS 设置有误"},
	{regexp.MustCompile(`(?i)i/o timeout|context deadline|timeout`), "网络超时"},
}

// friendlyError prefixes a Chinese reason to a core error (errors already in Chinese pass through).
func friendlyError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if hasCJK(msg) {
		return err
	}
	for _, h := range errHints {
		if h.re.MatchString(msg) {
			return fmt.Errorf("%s：%w", h.hint, err)
		}
	}
	return fmt.Errorf("配置无效：%w", err)
}

// FriendlyError is the same mapping for messages the app gets from elsewhere (validation, reload).
func FriendlyError(msg string) string {
	if msg == "" {
		return ""
	}
	return friendlyError(errors.New(msg)).Error()
}

func hasCJK(s string) bool {
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
	}
	return false
}

// missingGeo lists geo databases the runtime config needs but home does not have (or has truncated).
func missingGeo(home string, rt []byte) []string {
	text := string(rt)
	need := map[string]string{}
	if strings.Contains(text, "GEOSITE,") || strings.Contains(text, "geosite:") {
		need["GeoSite.dat"] = ""
	}
	if strings.Contains(text, "GEOIP,") || strings.Contains(text, "geoip:") {
		need["geoip.metadb"] = ""
	}
	if strings.Contains(text, "IP-ASN,") {
		need["ASN.mmdb"] = ""
	}
	var out []string
	for _, g := range geoKinds {
		if _, ok := need[g.File]; !ok {
			continue
		}
		fi, err := os.Stat(findCI(home, g.File))
		if err != nil || fi.Size() < 64*1024 {
			out = append(out, g.File)
		}
	}
	return out
}
