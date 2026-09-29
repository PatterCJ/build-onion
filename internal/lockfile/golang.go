package lockfile

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

func init() {
	register("golang", func(base string) bool { return base == "go.sum" }, parseGoSum)
}

// parseGoSum lists every module version whose content (not just go.mod) is
// pinned. The main module comes from the go.mod beside it.
func parseGoSum(data []byte, sibling Sibling) (Result, error) {
	var res Result
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 || !strings.HasPrefix(f[2], "h1:") {
			return res, fmt.Errorf("line %d: want \"module version h1:hash\"", n)
		}
		if strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		res.Packages = append(res.Packages, Package{Name: f[0], Version: f[1], Hash: f[2]})
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	if sibling != nil {
		mod, err := sibling("go.mod")
		if err != nil {
			return res, fmt.Errorf("go.mod beside go.sum: %w", err)
		}
		name, err := goModulePath(mod)
		if err != nil {
			return res, err
		}
		res.Local = append(res.Local, Local{Name: name})
	}
	return res, nil
}

func goModulePath(mod []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(mod))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[0] == "module" {
			return strings.Trim(f[1], `"`), nil
		}
	}
	return "", fmt.Errorf("go.mod: no module directive")
}
