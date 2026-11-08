package check

import (
	"regexp"
	"strings"
)

type licenseKind int

const (
	licUnknown licenseKind = iota
	licOSI
	licSourceAvail // a recognised source-available licence, accepted at either visibility
	licNonOSI      // restricted, looks open but is neither OSI nor recognised source-available
	licProprietary
)

var (
	wsRE          = regexp.MustCompile(`\s+`)
	proprietaryRE = regexp.MustCompile(`copyright (\(c\)|©) \d{4}(-\d{4})? .{2,80}?\. all rights reserved`)

	// sourceAvailMarkers recognises the deliberate source-available
	// licences by a distinctive phrase from each canonical text:
	//   PolyForm: https://polyformproject.org/licenses/<variant>/1.0.0.txt
	//   PolyForm Perimeter (site URL retired; text at source):
	//     https://github.com/polyformproject/polyform-licenses/blob/1.0.0/PolyForm-Perimeter-1.0.0.md
	//   FSL: https://fsl.software/FSL-1.1-MIT.template.md and
	//        https://fsl.software/FSL-1.1-ALv2.template.md (fslRE)
	//   BSL: https://mariadb.com/bsl11/
	// Checked before the non-OSI markers, whose broad family words
	// ("polyform", "business source license", "noncommercial") would claim
	// these texts first, and before the OSI phrases, because the FSL embeds
	// an MIT or Apache grant.
	sourceAvailMarkers = []struct{ marker, name string }{
		{"polyform noncommercial license", "PolyForm Noncommercial"},
		{"polyform small business license", "PolyForm Small Business"},
		{"polyform shield license", "PolyForm Shield"},
		{"polyform internal use license", "PolyForm Internal Use"},
		{"polyform free trial license", "PolyForm Free Trial"},
		{"polyform perimeter license", "PolyForm Perimeter"},
		{"polyform strict license", "PolyForm Strict"},
		{"business source license 1.1", "BSL-1.1"},
	}
	// fslRE matches the FSL title: the template says "ALv2 Future License",
	// the text published at fsl.software says "Apache 2.0 Future License".
	fslRE = regexp.MustCompile(`functional source license, version 1\.1,? (mit|alv2|apache 2\.0) future license`)
	// nonOSIMarkers names restricted licences by their title phrase. They
	// run before the OSI headers because these texts deliberately wrap or
	// embed an OSI licence: Commons Clause is a rider over Apache or MIT,
	// the SSPL is GPL-3.0 with one section replaced, and an Elastic or
	// Sustainable Use text can carry a permissive grant inside.
	nonOSIMarkers = []struct{ marker, name string }{
		{"commons clause", "Commons Clause"},
		{"business source license", "BSL"},
		{"polyform", "PolyForm"},
		{"elastic license", "Elastic License"},
		{"server side public license", "SSPL"},
		{"functional source license", "FSL"},
		{"sustainable use license", "Sustainable Use License"},
	}
	// nonCommMarkers is the generic catch-all for licences that restrict
	// commercial use without naming a recognised licence (CC-BY-NC and
	// friends), or that add such a rider to an OSI text. GPL-family headers
	// are exempt: the canonical texts legitimately contain "noncommercial
	// distribution" (GPL-2.0 §3c) and "noncommercially" (GPL-3.0 and
	// AGPL-3.0 §6c). The canonical MPL-2.0 text does not contain the word.
	nonCommMarkers = []struct{ marker, name string }{
		{"noncommercial", "non-commercial licence"},
	}
)

func normalize(s string) string {
	return strings.TrimSpace(wsRE.ReplaceAllString(strings.ToLower(s), " "))
}

// classifyLicense recognises a licence text by signature phrases. The licence
// family is read from the header (titles such as "GNU GENERAL PUBLIC LICENSE"
// also appear inside the AGPL and LGPL texts as cross-references), the
// permissive ones from their grant sentence. Order is load-bearing: named
// source-available and restricted licences first (their texts embed or wrap
// an OSI licence), then the OSI headers; the generic non-commercial marker
// applies to every OSI text except the GPL family.
func classifyLicense(text string) (licenseKind, string) {
	n := normalize(text)
	head := n
	if len(head) > 500 {
		head = head[:500]
	}
	for _, m := range sourceAvailMarkers {
		if strings.Contains(n, m.marker) {
			return licSourceAvail, m.name
		}
	}
	if m := fslRE.FindStringSubmatch(n); m != nil {
		if m[1] == "mit" {
			return licSourceAvail, "FSL-1.1-MIT"
		}
		return licSourceAvail, "FSL-1.1-ALv2"
	}
	for _, m := range nonOSIMarkers {
		if strings.Contains(n, m.marker) {
			return licNonOSI, m.name
		}
	}
	if name := osiLicense(n, head); name != "" {
		// A rider can sit on any OSI text; only the GPL family's own canonical
		// texts legitimately say "noncommercial", so only they skip the marker.
		if !strings.HasSuffix(name, "GPL") {
			if m := nonCommMarker(n); m != "" {
				return licNonOSI, m
			}
		}
		return licOSI, name
	}
	if m := nonCommMarker(n); m != "" {
		return licNonOSI, m
	}
	if proprietaryRE.MatchString(n) {
		return licProprietary, "proprietary notice"
	}
	return licUnknown, ""
}

func nonCommMarker(n string) string {
	for _, m := range nonCommMarkers {
		if strings.Contains(n, m.marker) {
			return m.name
		}
	}
	return ""
}

// osiLicense names the OSI licence whose header or grant sentence n carries,
// or "".
func osiLicense(n, head string) string {
	switch {
	case strings.Contains(head, "apache license") && strings.Contains(head, "version 2.0"):
		return "Apache-2.0"
	case strings.Contains(head, "mozilla public license") && strings.Contains(head, "2.0"):
		return "MPL-2.0"
	case strings.Contains(head, "gnu affero general public license"):
		return "AGPL"
	case strings.Contains(head, "gnu lesser general public license"),
		strings.Contains(head, "gnu library general public license"):
		return "LGPL"
	case strings.Contains(head, "gnu general public license"):
		return "GPL"
	case strings.Contains(head, "eclipse public license"):
		return "EPL"
	case strings.Contains(n, "permission is hereby granted, free of charge"):
		return "MIT"
	case strings.Contains(n, "redistribution and use in source and binary forms"):
		if strings.Contains(n, "neither the name of") {
			return "BSD-3-Clause"
		}
		return "BSD-2-Clause"
	case strings.Contains(n, "permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"):
		return "ISC"
	case strings.Contains(n, "this is free and unencumbered software released into the public domain"):
		return "Unlicense"
	}
	return ""
}

func checkLicense(vis Visibility, name string, data []byte) []Finding {
	kind, lic := classifyLicense(string(data))
	f := func(msg string) []Finding {
		return []Finding{{Check: License, Path: name, Msg: msg}}
	}
	// The owner decides the licence; the check requires a recognised one.
	// Public accepts OSI-approved, recognised source-available (PolyForm,
	// FSL-1.1, BSL-1.1) or the proprietary notice, and private the same
	// three — a private repo may already carry the licence it will be
	// published under.
	switch kind {
	case licOSI, licSourceAvail, licProprietary:
		return nil
	case licNonOSI:
		return f(string(vis) + " repo carries a non-OSI licence (" + lic + "); expected an OSI-approved or recognised source-available licence, or a proprietary notice")
	}
	return f("unrecognised licence text; expected an OSI-approved licence (MIT, Apache-2.0, BSD, MPL, GPL family, ISC, Unlicense, EPL), a recognised source-available licence (PolyForm, FSL-1.1, BSL-1.1) or a proprietary notice")
}
