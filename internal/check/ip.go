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

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

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
			trimmed == run && i < n && ipRightBad(line[i]) ||
			ipContext(line, s, i, run) {
			continue
		}
		if a, ok := parseIPRun(trimmed); ok && routableIP(a) {
			return true
		}
	}
	return false
}

// ipContext reports whether a run is something else than an address whatever
// its bytes parse as: a version string, a CIDR range, a section reference, a
// slice expression or one number in a run of numbers. s and i bound the
// maximal run in line.
func ipContext(line string, s, i int, run string) bool {
	return ipPrecededByVersion(line, s) ||
		ipSectionRef(line, s) ||
		ipFollowedByDigitTail(line, i) ||
		ipSliceIndex(line, s, run) ||
		ipInNumericBlob(line, s, i)
}

// ipPrecededByVersion: the literal follows a version marker — a product token
// and slash ("Chrome/139.0.0.0"), a bare "v" tag connector ("v=1.2.3.4") or a
// version keyword within the preceding 12 bytes ("since 1.2.3.4"). A
// lowercase path segment before the slash ("logs/1.2.3.4") stays a finding:
// it names a file, not a product.
func ipPrecededByVersion(line string, s int) bool {
	if s >= 2 && line[s-1] == '/' {
		for k := s - 2; k >= 0 && (isUpper(line[k]) || isLow(line[k])); k-- {
			if isUpper(line[k]) {
				return true
			}
		}
	}
	if s >= 2 && (line[s-2] == 'v' || line[s-2] == 'V') && strings.IndexByte("=#@", line[s-1]) >= 0 {
		return true
	}
	w := s - 12
	if w < 0 {
		w = 0
	}
	win := strings.ToLower(line[w:s])
	for _, kw := range []string{"since", "version", "ver", "@since"} {
		if j := strings.LastIndex(win, kw); j >= 0 &&
			(j == 0 || !isLow(win[j-1])) &&
			(j+len(kw) == len(win) || !isLow(win[j+len(kw)])) {
			return true
		}
	}
	return false
}

// ipSectionRef: a literal led by "§" is an RFC section reference (§4.1.1.1),
// not an address. A preceding ".digit" is the same shape and is already
// excluded by the left-boundary rule (a digit may not touch a run).
func ipSectionRef(line string, s int) bool {
	return s > 0 && line[s-1] == 0xA7
}

// ipFollowedByDigitTail: the literal continues as a network range
// ("1.2.3.0/24" names no host) or a longer dotted number ("1.3.6.1.4.1" —
// unreachable under a maximal run today, kept so a sub-run scan would still
// be safe).
func ipFollowedByDigitTail(line string, i int) bool {
	return i+1 < len(line) && (line[i] == '/' || line[i] == '.') && isDigit(line[i+1])
}

// ipSliceIndex: "::N" right after "[" is slice syntax (Go, Python), not an
// IPv6 literal.
func ipSliceIndex(line string, s int, run string) bool {
	if s == 0 || line[s-1] != '[' || len(run) < 3 || run[0] != ':' || run[1] != ':' {
		return false
	}
	for k := 2; k < len(run); k++ {
		if !isDigit(run[k]) {
			return false
		}
	}
	return true
}

// ipInNumericBlob: the literal sits inside a run of space-separated numbers —
// SVG path data, minified arrays — with at least eight numbers around it.
func ipInNumericBlob(line string, s, i int) bool {
	side := func(c byte) bool { return c == ' ' || c == '\t' || isDigit(c) }
	if s == 0 || i == len(line) || !side(line[s-1]) || !side(line[i]) {
		return false
	}
	lo := s
	for lo > 0 && isBlobByte(line[lo-1]) {
		lo--
	}
	hi := i
	for hi < len(line) && isBlobByte(line[hi]) {
		hi++
	}
	nums := 0
	for _, tok := range strings.Fields(line[lo:hi]) {
		if strings.IndexAny(tok, "0123456789") >= 0 {
			nums++
		}
	}
	return nums >= 8
}

func isBlobByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '.' || isDigit(c)
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
// RFC 5737 / RFC 3849 documentation ranges, CGNAT, the limited broadcast and
// the IANA special-purpose blocks ("this network" 0.0.0.0/8, IETF protocol
// assignments 192.0.0.0/24, 6to4 anycast 192.88.99.0/24, benchmarking
// 198.18.0.0/15, reserved 240.0.0.0/4, NAT64 64:ff9b::/96 and 64:ff9b:1::/48,
// 6to4 2002::/16, Teredo 2001::/32, ORCHIDv2 2001:20::/28, IPv4-compatible
// ::/96, discard-only 100::/64). Loopback, link-local, multicast, unspecified
// and private (RFC 1918, fc00::/7) are covered by netip predicates instead.
var nonRoutableIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("100::/64"),
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
	case !a.IsGlobalUnicast(), a.IsPrivate(), allowedIPs[a], placeholderIP(a):
		return false
	}
	for _, p := range nonRoutableIPPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// placeholderIP reports whether an address spells a placeholder rather than a
// host: four equal octets (2.2.2.2) or four counting up (1.2.3.4, 5.6.7.8).
func placeholderIP(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	o := a.As4()
	return o[0] == o[1] && o[1] == o[2] && o[2] == o[3] ||
		o[1] == o[0]+1 && o[2] == o[1]+1 && o[3] == o[2]+1
}
