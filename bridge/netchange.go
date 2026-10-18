package libmihomo

import (
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
)

// FlushDNSCache clears the core's DNS cache (the same as POST /cache/dns/flush). v0.19: the extension calls
// it after the physical network changes when 网络变化时清空 DNS 缓存 is on, so answers from the previous
// network are not reused. Fake-IP mappings are kept (flushing them would break open connections).
func FlushDNSCache() {
	resolver.ClearCache()
	log.Infoln("[DNS] cache cleared after a network change")
}
