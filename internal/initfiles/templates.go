package initfiles

import _ "embed"

// codeOfConduct is the Contributor Covenant 3.0, fetched 2026-11-07 from
// https://www.contributor-covenant.org/version/3/0/code_of_conduct/code_of_conduct.md
// with its two bracketed placeholders filled: the reporting channel carries the
// fixed GitHub advisory sentence and the enforcement note a neutral line, so
// the text holds no placeholder the stub-file check would flag.
//
//go:embed templates/code_of_conduct.md
var codeOfConduct string

// securityPublic is a SECURITY.md for a public repository. {{REPO}} becomes
// the GitHub OWNER/NAME for the private-advisory link.
//
//go:embed templates/security_public.md
var securityPublic string

//go:embed templates/security_private.md
var securityPrivate string

// apacheText is the canonical Apache-2.0 text from the SPDX
// license-list-data repository, fetched 2026-11-07 from
// https://raw.githubusercontent.com/spdx/license-list-data/main/text/Apache-2.0.txt
// verbatim, including its apply-the-licence appendix.
//
//go:embed templates/apache-2.0.txt
var apacheText string

// mitText is the canonical MIT text from the SPDX license-list-data
// repository, fetched 2026-11-07 from
// https://raw.githubusercontent.com/spdx/license-list-data/main/text/MIT.txt
// verbatim; "<year>" and "<copyright holders>" are filled in when written.
//
//go:embed templates/mit.txt
var mitText string

// proprietaryLicence is the private-repository LICENCE: the notice the
// licence check accepts plus a sentence that no licence is granted.
// {{YEAR}} and {{HOLDER}} are filled in when written.
//
//go:embed templates/license_proprietary.txt
var proprietaryLicence string

// The issue forms follow GitHub's issue-forms syntax (name, description,
// body[] items of type markdown/input/textarea/dropdown/checkboxes, each
// non-markdown item carrying id, attributes and validations).
//
//go:embed templates/bug_report.yml
var bugReportForm string

//go:embed templates/feature_request.yml
var featureRequestForm string

// issueConfigPublic holds the chooser configuration for a public repository;
// {{REPO}} becomes the GitHub OWNER/NAME for the advisory contact link.
//
//go:embed templates/issue_config_public.yml
var issueConfigPublic string

//go:embed templates/issue_config_private.yml
var issueConfigPrivate string

//go:embed templates/pull_request_template.md
var pullRequestTemplate string
