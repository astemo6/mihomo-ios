package mitm

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// IPv4 wildcard hostnames (v0.19.17, 喜马拉雅 report).
//
// QX / Surge / Loon modules list IP addresses with wildcards in [mitm] hostname, e.g. `180.153.*.*`,
// `114.80.139.2*`, `120.22*.2*.*`, `101.91.13*`: apps that resolve through HTTPDNS (喜马拉雅, 腾讯系,
// 抖音…) connect straight to an IP, so mihomo's metadata carries no host and a DOMAIN-WILDCARD rule
// (which matches the host only) never fires — those connections bypassed the engine and no rewrite or
// script ran. The engine itself matches the IP string with the same glob (globMatch), so the steering
// rule has to select exactly the IPv4 addresses whose dotted form the glob accepts. ipv4GlobPrefixes
// computes that set as CIDR prefixes (IP-CIDR rules match the destination IP).

// ipGlobMaxPrefixes caps the expansion; a pattern that needs more falls back to DOMAIN-WILDCARD.
const ipGlobMaxPrefixes = 1024

// isIPv4Glob reports whether p is an IPv4 address pattern with wildcards: only digits, dots, * and ?,
// at least one wildcard and at least one digit (a bare `*` stays a domain wildcard: it already matches
// every connection, IP-only ones included).
func isIPv4Glob(p string) bool {
	if !strings.ContainsAny(p, "*?") || !strings.ContainsAny(p, "0123456789") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= '0' && c <= '9' || c == '.' || c == '*' || c == '?') {
			return false
		}
	}
	return true
}

// globStates is a set of positions in the pattern (an NFA state set), kept sorted and closed over `*`.
type globStates []int

func (s globStates) key() string {
	var b strings.Builder
	for _, p := range s {
		b.WriteString(strconv.Itoa(p))
		b.WriteByte(',')
	}
	return b.String()
}

type ipGlob struct {
	pat  string
	memo map[string]int8 // state set + depth → 0 empty, 1 full, 2 partial
}

// closure adds p+1 for every `*` at p (a star may match nothing).
func (g *ipGlob) closure(in []int) globStates {
	seen := map[int]bool{}
	var out []int
	var add func(p int)
	add = func(p int) {
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
		if p < len(g.pat) && g.pat[p] == '*' {
			add(p + 1)
		}
	}
	for _, p := range in {
		add(p)
	}
	sort.Ints(out)
	return out
}

func (g *ipGlob) step(s globStates, c byte) globStates {
	var next []int
	for _, p := range s {
		if p >= len(g.pat) {
			continue
		}
		switch g.pat[p] {
		case '*':
			next = append(next, p)
		case '?':
			next = append(next, p+1)
		default:
			if g.pat[p] == c {
				next = append(next, p+1)
			}
		}
	}
	if len(next) == 0 {
		return nil
	}
	return g.closure(next)
}

func (g *ipGlob) feed(s globStates, octet int, first bool) globStates {
	if !first {
		s = g.step(s, '.')
	}
	for _, c := range []byte(strconv.Itoa(octet)) {
		if len(s) == 0 {
			return nil
		}
		s = g.step(s, c)
	}
	return s
}

func (g *ipGlob) accepts(s globStates) bool {
	for _, p := range s {
		if p == len(g.pat) {
			return true
		}
	}
	return false
}

// class reports whether every (1), no (0) or some (2) completion of the depth octets read so far
// (state set s) is accepted. Memoised on (s, depth), so `*.*.*.5`-style patterns stay cheap.
func (g *ipGlob) class(s globStates, depth int) int8 {
	if len(s) == 0 {
		return 0
	}
	if depth == 4 {
		if g.accepts(s) {
			return 1
		}
		return 0
	}
	k := s.key() + "|" + strconv.Itoa(depth)
	if v, ok := g.memo[k]; ok {
		return v
	}
	full, empty := true, true
	for v := 0; v < 256; v++ {
		switch g.class(g.feed(s, v, depth == 0), depth+1) {
		case 0:
			full = false
		case 1:
			empty = false
		default:
			full, empty = false, false
		}
	}
	var r int8 = 2
	if full {
		r = 1
	} else if empty {
		r = 0
	}
	g.memo[k] = r
	return r
}

type ipRange struct{ lo, hi uint32 }

// ipv4GlobPrefixes returns the CIDR prefixes covering exactly the IPv4 addresses whose dotted-decimal
// form matches the glob pat (`*` any run of characters, dots included; `?` one character), or ok=false
// when pat is not an IPv4 glob, matches nothing, or needs more than ipGlobMaxPrefixes prefixes.
func ipv4GlobPrefixes(pat string) (out []netip.Prefix, ok bool) {
	if !isIPv4Glob(pat) {
		return nil, false
	}
	g := &ipGlob{pat: pat, memo: map[string]int8{}}
	start := g.closure([]int{0})
	var ranges []ipRange
	var walk func(s globStates, depth int, base uint32) bool
	walk = func(s globStates, depth int, base uint32) bool {
		switch g.class(s, depth) {
		case 0:
			return true
		case 1:
			size := uint32(1) << (8 * (4 - depth))
			if depth == 0 {
				ranges = append(ranges, ipRange{0, ^uint32(0)})
				return true
			}
			if n := len(ranges); n > 0 && ranges[n-1].hi+1 == base {
				ranges[n-1].hi = base + size - 1
			} else {
				ranges = append(ranges, ipRange{base, base + size - 1})
			}
			return len(ranges) <= ipGlobMaxPrefixes
		}
		shift := 8 * (3 - depth)
		for v := 0; v < 256; v++ {
			if !walk(g.feed(s, v, depth == 0), depth+1, base|uint32(v)<<shift) {
				return false
			}
		}
		return true
	}
	if !walk(start, 0, 0) || len(ranges) == 0 {
		return nil, false
	}
	for _, r := range ranges {
		out = appendRangePrefixes(out, r.lo, r.hi)
		if len(out) > ipGlobMaxPrefixes {
			return nil, false
		}
	}
	return out, true
}

// appendRangePrefixes appends the minimal CIDR list for [lo, hi].
func appendRangePrefixes(out []netip.Prefix, lo, hi uint32) []netip.Prefix {
	for {
		bits := 32
		for bits > 0 {
			size := uint64(1) << (32 - (bits - 1))
			if uint64(lo)%size != 0 || uint64(lo)+size-1 > uint64(hi) {
				break
			}
			bits--
		}
		a := netip.AddrFrom4([4]byte{byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)})
		out = append(out, netip.PrefixFrom(a, bits))
		next := uint64(lo) + uint64(1)<<(32-bits)
		if next > uint64(hi) {
			return out
		}
		lo = uint32(next)
	}
}
