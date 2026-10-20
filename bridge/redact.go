package libmihomo

// Redaction for the diagnostic bundle (诊断 → 导出诊断包). Everything that leaves the device through
// the share sheet passes through here: server addresses, passwords, UUIDs, keys, subscription URLs and
// tokens are replaced, and every value removed from the config is also scrubbed from the log text.

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const redacted = "<redacted>"

// sensitiveKeys are config keys whose values are secrets or identify the user's servers, wherever they
// appear (proxies, plugin-opts, ws-opts headers, reality-opts, wireguard peers, top-level secret, …).
var sensitiveKeys = map[string]bool{
	"server": true, "servername": true, "sni": true, "host": true, "ip": true, "ipv6": true, "endpoint": true,
	"server-name": true, "peer": true,
	"password": true, "passwd": true, "pass": true, "obfs-password": true, "auth": true, "auth-str": true, "auth_str": true,
	"uuid": true, "username": true, "user": true, "users": true, "authentication": true,
	"private-key": true, "public-key": true, "pre-shared-key": true, "psk": true, "key": true, "seed": true,
	"short-id": true, "token": true, "secret": true, "obfs-param": true, "protocol-param": true,
	"ech-config": true, "certificate": true, "private-key-passphrase": true, "grpc-service-name": true,
	"path": true, "reserved": true, "client-fingerprint-secret": true, "access-token": true, "api-key": true,
	"authorization": true, "cookie": true,
}

// fullURLKeys hold URLs that are personal (subscription links, proxy-provider URLs): removed entirely.
var fullURLSections = map[string]bool{"proxy-providers": true}

var (
	reUUID     = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reURLQuery = regexp.MustCompile(`(?i)\b((?:https?|wss?)://[^\s?#"'<>]+)[?#][^\s"'<>]*`)
	reURLUser  = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@"'<>]+@`)
	reKV       = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|uuid|private-key|public-key|psk|auth|access_token|api_key)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&}"']+)`)
	reIPv4     = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	reBearer   = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`)
	reTokenSeg = regexp.MustCompile(`^[A-Za-z0-9_\-]{6,}$`)
)

// redactor collects every secret it removed so the same strings can be scrubbed from free text.
type redactor struct {
	secrets map[string]bool
}

func newRedactor() *redactor { return &redactor{secrets: map[string]bool{}} }

func (r *redactor) remember(s string) {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return // too short to scrub safely from logs (would hit unrelated text)
	}
	r.secrets[s] = true
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		if h := u.Hostname(); len(h) >= 4 {
			r.secrets[h] = true
		}
	}
}

// value redacts a decoded YAML / JSON value. section is the top-level key it lives under.
func (r *redactor) value(v any, key, section string) any {
	lk := strings.ToLower(key)
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = r.value(vv, k, section)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			// list items inherit the parent key (e.g. authentication: ["user:pass"])
			out[i] = r.value(vv, key, section)
		}
		return out
	case string:
		if sensitiveKeys[lk] && !(lk == "path" && section != "proxies") {
			if t == "" {
				return t
			}
			if lk == "path" && (t == "/" || !strings.ContainsAny(t, "?=&") && len(t) < 6) {
				return t // "/" or "/ws": harmless and useful for debugging
			}
			r.remember(t)
			return redacted
		}
		if lk == "url" || strings.HasSuffix(lk, "-url") || strings.Contains(t, "://") {
			if fullURLSections[section] || lk == "url" && section == "profiles" {
				r.remember(t)
				return "<redacted-url>"
			}
			return r.sanitizeURL(t)
		}
		return t
	default:
		if sensitiveKeys[lk] && v != nil {
			switch v.(type) {
			case bool:
				return v
			}
			return redacted
		}
		return v
	}
}

// config redacts a whole mihomo config map (top-level keys pass their own name as the section).
func (r *redactor) config(raw map[string]any) map[string]any {
	out := make(map[string]any, len(raw))
	for k, v := range raw {
		out[k] = r.value(v, k, k)
	}
	return out
}

// sanitizeURL keeps scheme, host and the readable path of public URLs (rule sets, modules, DoH) but drops
// credentials, query, fragment and path segments that look like tokens.
func (r *redactor) sanitizeURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return s
	}
	changed := false
	if u.User != nil {
		r.remember(u.User.String())
		u.User = nil
		changed = true
	}
	if u.RawQuery != "" || u.Fragment != "" {
		r.remember(u.RawQuery)
		u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
		changed = true
	}
	segs := strings.Split(u.Path, "/")
	for i, seg := range segs {
		if looksLikeToken(seg) {
			r.remember(seg)
			segs[i] = "<token>"
			changed = true
		}
	}
	if !changed {
		return s
	}
	return u.Scheme + "://" + u.Host + strings.Join(segs, "/")
}

// looksLikeToken: long or mixed letter+digit path segments (subscription tokens, NextDNS ids, keys).
// Version numbers ("v1.19.32") and words ("geoip", "release") stay.
func looksLikeToken(seg string) bool {
	if !reTokenSeg.MatchString(seg) {
		return false
	}
	var letters, digits int
	for _, c := range seg {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letters++
		}
	}
	if len(seg) >= 20 && digits > 0 {
		return true
	}
	return letters > 0 && digits >= 2 && len(seg) >= 6 && !strings.Contains(seg, "-") && !strings.Contains(seg, "_")
}

// text scrubs free text (logs, errors): every remembered secret, UUIDs, URL queries / credentials,
// key=value secrets, bearer tokens, and public IPv4 addresses (last two octets masked).
func (r *redactor) text(s string) string {
	if len(r.secrets) > 0 {
		list := make([]string, 0, len(r.secrets))
		for k := range r.secrets {
			list = append(list, k)
		}
		sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
		pairs := make([]string, 0, 2*len(list))
		for _, k := range list {
			pairs = append(pairs, k, redacted)
		}
		s = strings.NewReplacer(pairs...).Replace(s)
	}
	s = reUUID.ReplaceAllString(s, "<uuid>")
	s = reURLUser.ReplaceAllString(s, "$1<redacted>@")
	s = reURLQuery.ReplaceAllString(s, "$1?<redacted>")
	s = reKV.ReplaceAllString(s, "$1$2<redacted>")
	s = reBearer.ReplaceAllString(s, "$1 <redacted>")
	s = reIPv4.ReplaceAllStringFunc(s, maskIPv4)
	s = redactShareLinks(s)
	return s
}

// Review 5 P1-2: share-link credentials the rules above miss in free text — a legacy
// ss://BASE64(method:password@host:port) link has no "@" outside the base64, and subscription URLs carry
// their token in the path (https://host/link/<token>, /s/<token>). Kept separate from the key/value rules.
var (
	reSSLegacy = regexp.MustCompile(`(?i)\bss://[A-Za-z0-9+/=_-]{16,}`)
	reURLPath  = regexp.MustCompile(`(?i)\b((?:https?|wss?)://[^\s/?#"'<>]+)(/[^\s?#"'<>]*)`)
)

func redactShareLinks(s string) string {
	s = reSSLegacy.ReplaceAllString(s, "ss://<redacted>")
	return reURLPath.ReplaceAllStringFunc(s, func(m string) string {
		sub := reURLPath.FindStringSubmatch(m)
		if len(sub) != 3 {
			return m
		}
		segs := strings.Split(sub[2], "/")
		changed := false
		for i, seg := range segs {
			if seg != "" && looksLikeToken(seg) {
				segs[i] = redacted
				changed = true
			}
		}
		if !changed {
			return m
		}
		return sub[1] + strings.Join(segs, "/")
	})
}

// maskIPv4 keeps private, loopback, fake-ip (198.18/15) and link-local addresses, masks public ones.
func maskIPv4(s string) string {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return s
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return s
	}
	if _, fake, _ := net.ParseCIDR("198.18.0.0/15"); fake.Contains(ip) {
		return s
	}
	// Public DNS resolvers are not personal; keep them readable.
	switch s {
	case "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "223.5.5.5", "223.6.6.6", "119.29.29.29", "114.114.114.114", "9.9.9.9":
		return s
	}
	p := strings.Split(s, ".")
	return p[0] + "." + p[1] + ".x.x"
}
