package check

import (
	"net/netip"
	"strings"
)

// An IP literal candidate is a maximal run of IPv4/IPv6 characters: digits,
// hex letters, dots and colons. Version strings, OIDs and other dotted
// sequences are excluded first by the run boundaries and then by netip
// itself: "v1.2.3.4" (letter before the run), "1.2.3.4-beta" (hyphen after),
// "1.3.6.1.4.1" (fails to parse as one address).
func isIPRunChar(c byte) bool {
	return c >= '0' && c <= '9' || c == '.' || c == ':' ||
		c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// A run glued to a word or a longer version string is not an address: the
// neighbours may not be letters, digits (v1.2.3.4, x1.2.3.4) or a hyphen
// (1.2.3.4-beta). Dot and colon cannot neighbour a maximal run by definition.
func ipLeftBad(c byte) bool  { return isAlnum(c) || c == '-' || c == '_' }
func ipRightBad(c byte) bool { return isAlnum(c) || c == '-' }

// ipLiteralHit reports whether the line carries a globally routable IP
// literal. One hit per line is enough; the finding never names the value.
func ipLiteralHit(line string) bool {
	n := len(line)
	for i := 0; i < n; {
		if !isIPRunChar(line[i]) {
			i++
			continue
		}
		s := i
		for i < n && isIPRunChar(line[i]) {
			i++
		}
		run := line[s:i]
		trimmed := strings.TrimRight(run, ":.")
		if trimmed == "" || s > 0 && ipLeftBad(line[s-1]) ||
			trimmed == run && i < n && ipRightBad(line[i]) {
			continue
		}
		if a, ok := parseIPRun(trimmed); ok && routableIP(a) {
			return true
		}
	}
	return false
}

// parseIPRun turns a candidate run into an address. The run must carry a
// digit (keeps "dead:beef" and "aa:bb:cc:dd:ee:ff" out) and a dot or colon.
// An optional :port is accepted.
func parseIPRun(run string) (netip.Addr, bool) {
	if !strings.ContainsAny(run, "0123456789") || !strings.ContainsAny(run, ".:") {
		return netip.Addr{}, false
	}
	if hp, err := netip.ParseAddrPort(run); err == nil {
		return hp.Addr(), true
	}
	if a, err := netip.ParseAddr(run); err == nil {
		return a, true
	}
	return netip.Addr{}, false
}

// Ranges that parse as global unicast but are not routable addresses: the
// RFC 5737 / RFC 3849 documentation ranges, CGNAT and the limited broadcast.
// Loopback, link-local, multicast, unspecified and private (RFC 1918,
// fc00::/7) are covered by netip predicates instead.
var nonRoutableIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// Well-known public resolvers documented everywhere; a literal mention of
// one names no operator machine.
var allowedIPs = func() map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	for _, s := range []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
		"9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
		"2606:4700:4700::1111", "2606:4700:4700::1001",
		"2001:4860:4860::8888", "2001:4860:4860::8844",
		"2620:fe::fe", "2620:fe::9", "2620:119:35::35", "2620:119:53::53",
	} {
		m[netip.MustParseAddr(s)] = true
	}
	return m
}()

func routableIP(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case !a.IsGlobalUnicast(), a.IsPrivate(), allowedIPs[a]:
		return false
	}
	for _, p := range nonRoutableIPPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
