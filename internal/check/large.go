package check

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// A tracked file past this size is almost always a built artefact or a data
// dump that does not belong in git. Applies to public and private repos.
const largeFileLimit = 10 << 20

var lfsPointerPrefix = []byte("version https://git-lfs.github.com/spec/v1")

// checkLargeFiles flags tracked regular files over 10 MiB outside testdata/
// and third-party trees (the same vendored set the personal-data scan skips),
// other than Git LFS pointer stubs. The finding names the size, nothing else.
func checkLargeFiles(root string, files []string) []Finding {
	var out []Finding
	for _, f := range files {
		if hasSegment(f, "testdata") || isVendored(f) {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(f))
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() <= largeFileLimit || isLFSPointer(p) {
			continue
		}
		out = append(out, Finding{Check: LargeFile, Path: f,
			Msg: fmt.Sprintf("tracked file is %.1f MiB, above the %d MiB limit",
				float64(st.Size())/(1<<20), largeFileLimit>>20)})
	}
	return out
}

func isLFSPointer(p string) bool {
	fh, err := os.Open(p)
	if err != nil {
		return false
	}
	defer fh.Close()
	buf := make([]byte, 128)
	n, _ := fh.Read(buf)
	return bytes.HasPrefix(buf[:n], lfsPointerPrefix)
}
