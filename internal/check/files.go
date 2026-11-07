package check

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// repoFiles lists the files that count as part of the repository, as
// slash-separated paths relative to root. In a git work tree that is exactly
// the tracked set (`git ls-files`): an ignored build artefact is not part of
// the project. Outside a git work tree it is every file except .git/, and
// notGit is true so the caller can say so. A git work tree where git fails
// (missing binary, ownership refusal) is an error, never a silent walk.
func repoFiles(root string) (files []string, notGit bool, err error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached")
	out, gitErr := cmd.Output()
	if gitErr == nil {
		for _, p := range bytes.Split(out, []byte{0}) {
			if len(p) > 0 {
				files = append(files, string(p))
			}
		}
		sort.Strings(files)
		return files, false, nil
	}
	if _, statErr := os.Lstat(filepath.Join(root, ".git")); statErr == nil {
		return nil, false, fmt.Errorf("git ls-files failed in a git work tree: %w", gitErr)
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(files)
	return files, true, err
}

// readRegular reads a file only when it is a regular file inside root. A
// symlink or submodule entry returns ok=false: following a tracked symlink
// would let a repository make the scanner read files outside itself.
func readRegular(root, rel string, limit int64) (data []byte, ok bool) {
	p := filepath.Join(root, filepath.FromSlash(rel))
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, false
	}
	data, err = os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return data, true
}

func hasSegment(path, seg string) bool {
	for _, s := range strings.Split(path, "/") {
		if s == seg {
			return true
		}
	}
	return false
}
