package lockfile

import (
	"encoding/json"
	"fmt"
	"strings"
)

func init() {
	register("npm", func(base string) bool {
		return base == "package-lock.json" || base == "npm-shrinkwrap.json"
	}, parseNpmLock)
}

// npmEntry is a v2/v3 "packages" entry. Its "dependencies" are version
// ranges, not pinned packages, and are not read.
type npmEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	Link    bool   `json:"link"`
}

// npmV1Entry is a lockfileVersion 1 "dependencies" entry, which nests.
type npmV1Entry struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]npmV1Entry `json:"dependencies"`
}

// parseNpmLock reads package-lock.json v1, v2 and v3.
func parseNpmLock(data []byte, _ Sibling) (Result, error) {
	var lock struct {
		Name            string                `json:"name"`
		LockfileVersion int                   `json:"lockfileVersion"`
		Packages        map[string]npmEntry   `json:"packages"`
		Dependencies    map[string]npmV1Entry `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	var res Result
	if len(lock.Packages) > 0 { // v2, v3: flat map keyed by install path
		for key, e := range lock.Packages {
			switch {
			case key == "":
				if e.Name != "" {
					res.Local = append(res.Local, Local{Name: e.Name})
				}
				continue
			case e.Link:
				// A workspace member, built from this source.
				res.Local = append(res.Local, Local{Name: npmNameFromPath(key)})
				continue
			case !strings.Contains(key, "node_modules/"):
				// A workspace folder's own entry; its link above names it.
				continue
			}
			name := e.Name
			if name == "" {
				name = npmNameFromPath(key)
			}
			if e.Version == "" {
				return Result{}, fmt.Errorf("%s: no version", key)
			}
			res.Packages = append(res.Packages, Package{Name: name, Version: e.Version, Dev: e.Dev})
		}
		return res, nil
	}
	if lock.LockfileVersion == 1 || len(lock.Dependencies) > 0 {
		if lock.Name != "" {
			res.Local = append(res.Local, Local{Name: lock.Name})
		}
		var walk func(map[string]npmV1Entry)
		walk = func(deps map[string]npmV1Entry) {
			for name, e := range deps {
				res.Packages = append(res.Packages, Package{Name: name, Version: e.Version, Dev: e.Dev})
				walk(e.Dependencies)
			}
		}
		walk(lock.Dependencies)
		return res, nil
	}
	return Result{}, fmt.Errorf("no packages: unrecognized lockfile layout (lockfileVersion %d)", lock.LockfileVersion)
}

// npmNameFromPath takes the package name from an install path:
// node_modules/a/node_modules/@scope/b → @scope/b.
func npmNameFromPath(key string) string {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 {
		return key
	}
	return key[i+len("node_modules/"):]
}
