package libmihomo

import (
	"testing"
)

// regionCorpus mixes flag emoji, CJK names, English names, lookaround-only codes and
// near-miss names (印度尼西亚 must be ID, not IN).
var regionCorpus = []string{
	"🇭🇰 香港 01", "香港|HKT|高速", "深港专线 02", "Hong Kong 05", "HongKong IEPL",
	"HK 01", "HKG-03", "澳门 01", "Macau 02", "Macao",
	"台湾 01", "台北 02", "Taiwan 03", "TW-04", "TWN",
	"日本 01", "东京 02", "Tokyo 03", "Osaka", "JP-05", "JPN",
	"新加坡 01", "狮城 02", "Singapore 03", "SG-04", "SGP",
	"韩国 01", "首尔 02", "Korea 03", "Seoul", "KR-04",
	"美国 01", "洛杉矶 02", "Los Angeles 03", "San Jose", "New York", "Silicon Valley", "USA", "US-04",
	"加拿大 01", "Toronto", "CA-02", "英国 伦敦", "London 01", "UK", "GB-02",
	"德国 法兰克福", "Frankfurt", "DE-01", "法国 巴黎", "Paris", "FR-01",
	"荷兰 阿姆斯特丹", "Amsterdam", "NL-01", "俄罗斯 莫斯科", "Moscow", "RU-01",
	"印度 01", "孟买", "India", "IND-02", "印度尼西亚 01", "印尼 雅加达", "Jakarta", "IDN-02",
	"澳大利亚 悉尼", "Sydney", "AUS", "土耳其", "Istanbul", "Türkiye", "TUR",
	"马来西亚 吉隆坡", "Malaysia", "泰国 曼谷", "Bangkok", "越南 胡志明", "Vietnam",
	"菲律宾 马尼拉", "Philippines", "阿根廷", "Argentina", "巴西 圣保罗", "Brazil",
	"意大利 米兰", "Italy", "西班牙 马德里", "Spain", "瑞士 苏黎世", "Switzerland",
	"瑞典", "Sweden", "波兰", "Poland", "乌克兰", "Ukraine", "爱尔兰", "Ireland",
	"以色列", "Israel", "阿联酋 迪拜", "Dubai", "UAE", "南非", "South Africa",
	"尼日利亚", "Nigeria", "埃及", "Egypt", "墨西哥", "Mexico", "智利", "Chile",
	"新西兰", "New Zealand", "哈萨克", "Kazakhstan", "巴基斯坦", "Pakistan",
	"孟加拉", "Bangladesh", "柬埔寨", "Cambodia", "蒙古", "Mongolia",
	"中国 回国 01", "回国专线", "China 02", "CHN",
	"中转 01", "IEPL 专线", "游戏加速", "剩余流量 100G", "官网 example.com", "MO", "DE", "SG", "IN", "DO NOT USE",
	// Standalone-code tokens and near misses (guarded alternatives only).
	"HKG", "xHKG", "HKGx", "HK01", "1HK", "UK", "GB", "UK2", "GBUK", "UKGB", "a UK b", "UK.", ".UK",
	"IND", "KOR", "KR", "DEU", "MOP", "SGP", "TWN", "JPN", "USA", "CAN", "Indonesia", "India",
	"印度", "旧金山 San Francisco", "AUS 01", "TUR 02", "IDN", "VNM", "THA", "PHL", "MYS",
}

// referenceDetectRegion is the pre-optimization implementation: flag first, then a
// regexp2 scan in region order. The differential test pins detectRegion to it.
func referenceDetectRegion(name string) (string, int) {
	if f := firstFlag(name); f != "" {
		for i, r := range regions {
			if flagOf(r.code) == f {
				return r.code, i
			}
		}
	}
	for i, r := range regions {
		if ok, _ := r.re.MatchString(name); ok {
			return r.code, i
		}
	}
	return "", len(regions)
}

func TestDetectRegionMatchesRegexReference(t *testing.T) {
	names := append([]string{}, regionCorpus...)
	// Wrap corpus entries so matches occur mid-string and next to letters / digits.
	for _, n := range regionCorpus {
		names = append(names, "x "+n, n+" x", "", "v2-"+n+"-pro")
	}
	for _, n := range names {
		gc, gi := detectRegion(n)
		rc, ri := referenceDetectRegion(n)
		if gc != rc || gi != ri {
			t.Errorf("detectRegion(%q) = %q,%d; reference = %q,%d", n, gc, gi, rc, ri)
		}
	}
}

func BenchmarkDetectRegion(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, n := range regionCorpus {
			detectRegion(n)
		}
	}
}

// BenchmarkDetectRegionMisses is the worst case: names no region matches, so every
// pattern runs.
func BenchmarkDetectRegionMisses(b *testing.B) {
	misses := []string{"中转 01", "IEPL 专线", "游戏加速", "剩余流量 100G", "官网 example.com", "DO NOT USE", "倍率 2.0", "测试节点"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, n := range misses {
			detectRegion(n)
		}
	}
}
