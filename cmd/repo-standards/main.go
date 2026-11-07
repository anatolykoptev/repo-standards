// Command repo-standards checks a repository against the fleet's standard
// project documents and, for public repositories, scans for personal data.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anatolykoptev/repo-standards/internal/check"
	"github.com/anatolykoptev/repo-standards/internal/denylist"
)

const (
	exitOK        = 0
	exitViolation = 1
	exitUsage     = 2
	exitPanic     = 3
	secretMode    = 0o077 // group/other permission bits a plaintext list must not have
	defaultHashes = "internal/denylist/denylist.hashes"
)

const usage = `usage:
  repo-standards check [--visibility public|private] [--detected public|private]
                       [--denylist FILE] [--history] [path]
  repo-standards denylist-gen [--in FILE] [--out FILE]

check prints one line per finding and exits 1 if there are any.
--detected is the visibility the environment reports; it wins, and --visibility
may only be as strict or stricter. With neither flag the rule set is public.
--history scans the text of git log -p --all instead of the work tree.
Exit codes: 0 clean, 1 findings, 2 usage or I/O error, 3 internal error.
`

func main() { os.Exit(guarded(os.Args[1:], os.Stdout, os.Stderr)) }

// guarded turns a panic into exit 3 so CI can tell a crash from a usage error.
func guarded(args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "repo-standards: internal error: %v\n", r)
			code = exitPanic
		}
	}()
	return runFn(args, stdout, stderr)
}

// runFn is a variable so a test can make it panic.
var runFn = run

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "denylist-gen":
		return runGen(args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	vis := fs.String("visibility", "", "public or private (see --detected)")
	detected := fs.String("detected", "", "visibility reported by the environment; overrides --visibility")
	history := fs.Bool("history", false, "scan git log -p --all instead of the work tree")
	dlPath := fs.String("denylist", "", "hash file to use instead of the built-in list")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	} else if fs.NArg() == 1 {
		root = fs.Arg(0)
	}
	var (
		dl  *denylist.List
		err error
	)
	if *dlPath != "" {
		var f *os.File
		if f, err = os.Open(*dlPath); err == nil {
			dl, err = denylist.Parse(f)
			f.Close()
			if err == nil && dl.Len() == 0 {
				err = fmt.Errorf("%s holds no entries", *dlPath)
			}
		}
	} else {
		dl, err = denylist.Embedded()
	}
	if err != nil {
		fmt.Fprintln(stderr, "repo-standards:", err)
		return exitUsage
	}
	v, err := check.ResolveVisibility(*vis, *detected)
	if err != nil {
		fmt.Fprintln(stderr, "repo-standards:", err)
		return exitUsage
	}
	opts := check.Options{Root: root, Visibility: v, Denylist: dl}
	var res check.Result
	if *history {
		res, err = check.RunHistory(opts)
	} else {
		res, err = check.Run(opts)
	}
	if err != nil {
		fmt.Fprintln(stderr, "repo-standards:", err)
		return exitUsage
	}
	for _, f := range res.Findings {
		fmt.Fprintln(stdout, f)
	}
	if res.NotGit {
		fmt.Fprintln(stderr, "repo-standards: not a git work tree: every file was scanned, not only tracked ones")
	}
	for _, sp := range res.Stats.Suppressions {
		fmt.Fprintf(stderr, "repo-standards: suppressed %s:%d: %s\n", sp.Path, sp.Line, sp.Reason)
	}
	if v == check.Public {
		fmt.Fprintf(stderr, "repo-standards: skipped %d binary files, suppressed %d finding(s)\n",
			res.Stats.SkippedBinary, res.Stats.Suppressed)
	}
	if len(res.Findings) > 0 {
		fmt.Fprintf(stderr, "repo-standards: %d finding(s)\n", len(res.Findings))
		return exitViolation
	}
	return exitOK
}

func configDir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return d, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config"), nil
}

func runGen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("denylist-gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "plaintext list, category:token per line (default: <config>/repo-standards/denylist.txt)")
	out := fs.String("out", defaultHashes, "hash file to write")
	pubFile := fs.String("public-repos", "", "file of public repository names, one per line; matching tokens are dropped")
	pubOwner := fs.String("public-owner", "", "GitHub owner whose public repositories are listed with the gh CLI; matching tokens are dropped")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *in == "" {
		d, err := configDir()
		if err != nil {
			fmt.Fprintln(stderr, "repo-standards:", err)
			return exitUsage
		}
		*in = filepath.Join(d, "repo-standards", "denylist.txt")
	}
	st, err := os.Stat(*in)
	if err != nil {
		fmt.Fprintln(stderr, "repo-standards:", err)
		return exitUsage
	}
	// The plaintext list is the secret. Refuse a copy others can read.
	if st.Mode().Perm()&secretMode != 0 {
		fmt.Fprintf(stderr, "repo-standards: %s must not be readable by group or others (chmod 600)\n", *in)
		return exitUsage
	}
	f, err := os.Open(*in)
	if err != nil {
		fmt.Fprintln(stderr, "repo-standards:", err)
		return exitUsage
	}
	defer f.Close()

	var salt []byte
	if old, err := os.Open(*out); err == nil {
		if l, perr := denylist.Parse(old); perr == nil {
			salt = l.Salt()
		}
		old.Close()
	}
	exclude, err := publicNames(*pubFile, *pubOwner)
	if err != nil {
		fmt.Fprintln(stderr, "repo-standards:", err)
		return exitUsage
	}
	data, dropped, err := denylist.Generate(f, salt, exclude)
	if err != nil {
		fmt.Fprintln(stderr, "repo-standards:", err) // message names a line number, never a token
		return exitUsage
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(stderr, "repo-standards:", err)
		return exitUsage
	}
	l, _ := denylist.Parse(bytes.NewReader(data))
	fmt.Fprintf(stdout, "wrote %s (%d tokens); dropped %d that are public repository names (%d names known)\n",
		*out, l.Len(), dropped, len(exclude))
	return exitOK
}

// publicNames loads public repository names from a file or from gh. With
// neither flag nothing is excluded.
func publicNames(file, owner string) (map[string]bool, error) {
	var raw []byte
	switch {
	case file != "" && owner != "":
		return nil, fmt.Errorf("use only one of --public-repos and --public-owner")
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		raw = b
	case owner != "":
		b, err := exec.Command("gh", "repo", "list", owner, "--visibility", "public",
			"--limit", "1000", "--json", "name", "-q", ".[].name").Output()
		if err != nil {
			return nil, fmt.Errorf("gh repo list: %w", err)
		}
		raw = b
	default:
		return nil, nil
	}
	return denylist.PublicNames(strings.Fields(string(raw))), nil
}
