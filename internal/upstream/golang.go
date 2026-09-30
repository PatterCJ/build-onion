package upstream

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"

	"github.com/PatterCJ/build-onion/internal/lockfile"
)

// checkGo looks the module up in the Go checksum database. The client checks
// the log's signed tree head and the record's inclusion proof, so a match
// means the go.sum hash is the one every other Go user gets.
func (c *Checker) checkGo(p lockfile.Package, r *Result) {
	lines, err := c.sumdb.lookup(p.Name, p.Version)
	if err != nil {
		if errors.Is(err, errNotFound) {
			r.Outcome, r.Detail = NotFound, "not in the public checksum database"
			return
		}
		if errors.Is(err, errSecurity) {
			r.Outcome, r.Detail = Invalid, err.Error()
			return
		}
		r.Outcome, r.Detail = Error, err.Error()
		return
	}
	want := p.Name + " " + p.Version + " "
	for _, l := range lines {
		if h, ok := strings.CutPrefix(l, want); ok {
			if h != p.Hash {
				r.Outcome, r.Detail = Mismatch, fmt.Sprintf("go.sum pins %s, checksum database has %s", p.Hash, h)
				return
			}
			r.Outcome = Logged
			return
		}
	}
	r.Outcome, r.Detail = Error, "checksum database answered without this version's hash"
}

// errSecurity means the log's signed data didn't verify or contradicted
// itself: a forged or forked log, not a lookup failure.
var errSecurity = errors.New("checksum database failed verification")

// sumdbClient is an in-memory sumdb.ClientOps: nothing is cached between
// runs, so each check starts from the log's current signed tree head.
type sumdbClient struct {
	client *sumdb.Client
	base   string
	get    func(context.Context, string, string) ([]byte, error)

	mu       sync.Mutex
	config   map[string][]byte
	cache    map[string][]byte
	notFound map[string]bool
	security []string
}

func newSumdb(base, key string, get func(context.Context, string, string) ([]byte, error)) *sumdbClient {
	s := &sumdbClient{base: strings.TrimSuffix(base, "/"), get: get,
		config: map[string][]byte{"key": []byte(key)}, cache: map[string][]byte{}, notFound: map[string]bool{}}
	s.client = sumdb.NewClient(s)
	return s
}

func (s *sumdbClient) lookup(path, version string) ([]string, error) {
	lines, err := s.client.Lookup(path, version)
	if err == nil {
		return lines, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.security) > 0 {
		return nil, fmt.Errorf("%w: %s", errSecurity, strings.Join(s.security, "; "))
	}
	epath, _ := module.EscapePath(path)
	evers, _ := module.EscapeVersion(version)
	if s.notFound["/lookup/"+epath+"@"+evers] {
		return nil, errNotFound
	}
	return nil, err
}

func (s *sumdbClient) ReadRemote(path string) ([]byte, error) {
	b, err := s.get(context.Background(), s.base+path, "")
	if errors.Is(err, errNotFound) {
		s.mu.Lock()
		s.notFound[path] = true
		s.mu.Unlock()
	}
	return b, err
}

func (s *sumdbClient) ReadConfig(file string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config[file], nil
}

func (s *sumdbClient) WriteConfig(file string, old, new []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if string(s.config[file]) != string(old) {
		return sumdb.ErrWriteConflict
	}
	s.config[file] = new
	return nil
}

func (s *sumdbClient) ReadCache(file string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.cache[file]; ok {
		return b, nil
	}
	return nil, errNotFound
}

func (s *sumdbClient) WriteCache(file string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[file] = data
}

func (s *sumdbClient) Log(string) {}

func (s *sumdbClient) SecurityError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.security = append(s.security, msg)
}
