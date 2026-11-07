package check

import (
	"regexp"
	"strings"
)

type licenseKind int

const (
	licUnknown licenseKind = iota
	licOSI
	licNonOSI // source-available / restricted, looks open but is not OSI
	licProprietary
)

var (
	wsRE          = regexp.MustCompile(`\s+`)
	proprietaryRE = regexp.MustCompile(`copyright (\(c\)|©) \d{4}(-\d{4})? .{2,80}?\. all rights reserved`)
	nonOSIMarkers = []struct{ marker, name string }{
		{"commons clause", "Commons Clause"},
		{"business source license", "BSL"},
		{"polyform", "PolyForm"},
		{"elastic license", "Elastic License"},
		{"server side public license", "SSPL"},
		{"functional source license", "FSL"},
		{"sustainable use license", "Sustainable Use License"},
		{"noncommercial", "non-commercial licence"},
	}
)

func normalize(s string) string {
	return strings.TrimSpace(wsRE.ReplaceAllString(strings.ToLower(s), " "))
}

// classifyLicense recognises a licence text by signature phrases. The licence
// family is read from the header (titles such as "GNU GENERAL PUBLIC LICENSE"
// also appear inside the AGPL and LGPL texts as cross-references), the
// permissive ones from their grant sentence.
func classifyLicense(text string) (licenseKind, string) {
	n := normalize(text)
	head := n
	if len(head) > 500 {
		head = head[:500]
	}
	for _, m := range nonOSIMarkers {
		if strings.Contains(n, m.marker) {
			return licNonOSI, m.name
		}
	}
	switch {
	case strings.Contains(head, "apache license") && strings.Contains(head, "version 2.0"):
		return licOSI, "Apache-2.0"
	case strings.Contains(head, "mozilla public license") && strings.Contains(head, "2.0"):
		return licOSI, "MPL-2.0"
	case strings.Contains(head, "gnu affero general public license"):
		return licOSI, "AGPL"
	case strings.Contains(head, "gnu lesser general public license"),
		strings.Contains(head, "gnu library general public license"):
		return licOSI, "LGPL"
	case strings.Contains(head, "gnu general public license"):
		return licOSI, "GPL"
	case strings.Contains(head, "eclipse public license"):
		return licOSI, "EPL"
	case strings.Contains(n, "permission is hereby granted, free of charge"):
		return licOSI, "MIT"
	case strings.Contains(n, "redistribution and use in source and binary forms"):
		if strings.Contains(n, "neither the name of") {
			return licOSI, "BSD-3-Clause"
		}
		return licOSI, "BSD-2-Clause"
	case strings.Contains(n, "permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"):
		return licOSI, "ISC"
	case strings.Contains(n, "this is free and unencumbered software released into the public domain"):
		return licOSI, "Unlicense"
	}
	if proprietaryRE.MatchString(n) {
		return licProprietary, "proprietary notice"
	}
	return licUnknown, ""
}

func checkLicense(vis Visibility, name string, data []byte) []Finding {
	kind, lic := classifyLicense(string(data))
	f := func(msg string) []Finding {
		return []Finding{{Check: License, Path: name, Msg: msg}}
	}
	switch vis {
	case Public:
		switch kind {
		case licOSI:
			return nil
		case licNonOSI:
			return f("public repo carries a non-OSI licence (" + lic + "); expected an OSI-approved licence")
		case licProprietary:
			return f("public repo carries a proprietary notice; expected an OSI-approved licence")
		}
		return f("unrecognised licence text; expected an OSI-approved licence (MIT, Apache-2.0, BSD, MPL, GPL family, ISC, Unlicense, EPL)")
	default:
		switch kind {
		case licProprietary:
			return nil
		case licOSI:
			return f("private repo carries an OSI licence (" + lic + "); expected a proprietary notice: \"Copyright (c) <year> <holder>. All rights reserved.\"")
		case licNonOSI:
			return f("private repo carries a non-OSI licence (" + lic + "); expected a proprietary notice")
		}
		return f("unrecognised licence text; expected a proprietary notice: \"Copyright (c) <year> <holder>. All rights reserved.\"")
	}
}
