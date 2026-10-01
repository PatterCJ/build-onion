// Package egress is the filtering proxy that is the fetch step's only route
// to the network. The fetch container sits on a Docker network with no route
// out; the proxy is the one peer it can reach. Every request is checked
// against the manifest's allow-list by host and port, the host is resolved by
// the proxy itself, and the connection goes to an address the proxy checked,
// so neither DNS tricks nor a direct IP can reach anything else. Every
// attempt, allowed or denied, is logged.
//
// HTTPS is tunnelled with CONNECT and never intercepted: the proxy sees host
// names and ports, not paths or content.
package egress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PatterCJ/build-onion/internal/manifest"
)

// Entry is one logged connection attempt.
type Entry struct {
	Time    time.Time `json:"time"`
	Method  string    `json:"method"` // CONNECT, GET, …
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	Addr    string    `json:"addr,omitempty"` // the address actually dialled
	Allowed bool      `json:"allowed"`
	// Unlisted marks a connection outside the allow-list that report mode
	// let through: enforce mode would have denied it.
	Unlisted bool   `json:"unlisted,omitempty"`
	Reason   string `json:"reason,omitempty"`
	BytesOut int64  `json:"bytesOut"` // client → upstream
	BytesIn  int64  `json:"bytesIn"`  // upstream → client
}

// Proxy is an HTTP forward proxy restricted to an allow-list.
type Proxy struct {
	Rules []manifest.EgressRule
	// Log receives one JSON Entry per line. Writes are serialized.
	Log io.Writer

	// Resolve and CheckAddr are replaceable for tests; production uses the
	// system resolver and CheckAddr.
	Resolve   func(ctx context.Context, host string) ([]netip.Addr, error)
	CheckAddr func(addr netip.Addr, rule manifest.EgressRule) error
	// DialTimeout bounds DNS plus TCP connect.
	DialTimeout time.Duration
	// Report lets hosts outside Rules through, marking them Unlisted. The
	// address checks (loopback, link-local, metadata, private) still apply,
	// and IP-address targets are still refused.
	Report bool

	mu sync.Mutex
}

// Match finds the rule that allows host:port. Host must already be
// normalized (lowercase, no trailing dot).
func Match(rules []manifest.EgressRule, host string, port int) (manifest.EgressRule, bool) {
	for _, r := range rules {
		if r.EffectivePort() != port {
			continue
		}
		if suffix, ok := strings.CutPrefix(r.Host, "*."); ok {
			// Any subdomain, never the apex itself.
			if strings.HasSuffix(host, "."+suffix) {
				return r, true
			}
		} else if host == r.Host {
			return r, true
		}
	}
	return manifest.EgressRule{}, false
}

// Ranges that are never reachable, whatever a rule says.
var alwaysBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, including cloud metadata 169.254.169.254
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::/32"), // AWS IMDS over IPv6
}

// Ranges reachable only by a rule marked private.
var private = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT, used for internal networks
	netip.MustParsePrefix("fc00::/7"),
}

// CheckAddr decides whether a resolved address may be dialled for rule.
func CheckAddr(addr netip.Addr, rule manifest.EgressRule) error {
	addr = addr.Unmap() // ::ffff:127.0.0.1 is 127.0.0.1
	for _, p := range alwaysBlocked {
		if p.Contains(addr) {
			return fmt.Errorf("%s is in %s, which is never reachable", addr, p)
		}
	}
	if !rule.Private {
		for _, p := range private {
			if p.Contains(addr) {
				return fmt.Errorf("%s is a private address; the egress rule for %s would need private: true", addr, rule.Host)
			}
		}
	}
	return nil
}

func (p *Proxy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if p.Resolve != nil {
		return p.Resolve(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (p *Proxy) checkAddr(a netip.Addr, r manifest.EgressRule) error {
	if p.CheckAddr != nil {
		return p.CheckAddr(a, r)
	}
	return CheckAddr(a, r)
}

func (p *Proxy) log(e Entry) {
	if p.Log == nil {
		return
	}
	b, _ := json.Marshal(e)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Log.Write(append(b, '\n'))
}

// Denied is a policy decision: the target is not allowed. Any other dial
// error is a network failure reaching an allowed target.
type Denied struct{ Reason string }

func (d *Denied) Error() string { return d.Reason }

// dial resolves host itself and connects only to an address that passes the
// checks, so the address checked is the address used.
func (p *Proxy) dial(ctx context.Context, host string, port int) (conn net.Conn, addr string, unlisted bool, err error) {
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, "", false, &Denied{"IP addresses are not allowed; egress rules name hosts"}
	}
	rule, ok := Match(p.Rules, host, port)
	if !ok {
		if !p.Report {
			return nil, "", false, &Denied{fmt.Sprintf("%s:%d is not in the manifest's dependencies.egress", host, port)}
		}
		// Report mode: reach it under the default address checks.
		rule, unlisted = manifest.EgressRule{Host: host, Port: port}, true
	}
	timeout := p.DialTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := p.resolve(ctx, host)
	if err != nil {
		return nil, "", unlisted, fmt.Errorf("resolve %s: %w", host, err)
	}
	var blocked, failed []string
	var d net.Dialer
	for _, a := range addrs {
		if err := p.checkAddr(a, rule); err != nil {
			blocked = append(blocked, err.Error())
			continue
		}
		target := netip.AddrPortFrom(a.Unmap(), uint16(port)).String()
		c, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			failed = append(failed, err.Error())
			continue
		}
		return c, target, unlisted, nil
	}
	switch {
	case len(failed) > 0:
		// At least one address was permitted; reaching it failed.
		return nil, "", unlisted, errors.New(strings.Join(append(failed, blocked...), "; "))
	case len(blocked) > 0:
		return nil, "", unlisted, &Denied{strings.Join(blocked, "; ")}
	default:
		return nil, "", unlisted, fmt.Errorf("%s resolved to no addresses", host)
	}
}

// fail answers a dial error: a policy denial is logged as denied (403), a
// network failure to an allowed target as allowed-but-failed (502).
func (p *Proxy) fail(w http.ResponseWriter, e Entry, err error) {
	var d *Denied
	if errors.As(err, &d) {
		p.deny(w, e, d.Reason)
		return
	}
	e.Allowed, e.Reason = true, "upstream: "+err.Error()
	p.log(e)
	http.Error(w, "build-onion egress proxy: "+e.Reason, http.StatusBadGateway)
}

// ServeHTTP handles CONNECT tunnels and absolute-form plain HTTP requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.connect(w, r)
	case r.URL.IsAbs() && r.URL.Scheme == "http":
		p.forward(w, r)
	default:
		http.Error(w, "build-onion egress proxy: only CONNECT and absolute http:// requests are proxied", http.StatusBadRequest)
	}
}

func splitHostPort(hostport string, defaultPort int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		if defaultPort == 0 {
			return "", 0, err
		}
		host, portStr = hostport, strconv.Itoa(defaultPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return "", 0, errors.New("empty host")
	}
	return host, port, nil
}

func (p *Proxy) deny(w http.ResponseWriter, e Entry, reason string) {
	e.Allowed, e.Reason = false, reason
	p.log(e)
	http.Error(w, "build-onion egress proxy: denied: "+reason, http.StatusForbidden)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	e := Entry{Time: time.Now().UTC(), Method: r.Method}
	host, port, err := splitHostPort(r.Host, 0)
	if err != nil {
		p.deny(w, e, "bad CONNECT target: "+err.Error())
		return
	}
	e.Host, e.Port = host, port
	upstream, addr, unlisted, err := p.dial(r.Context(), host, port)
	e.Unlisted = unlisted
	if err != nil {
		p.fail(w, e, err)
		return
	}
	e.Addr = addr
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		p.deny(w, e, "connection can't be hijacked")
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		p.deny(w, e, "hijack: "+err.Error())
		return
	}
	e.Allowed = true
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		e.Reason = "client went away"
		p.log(e)
		return
	}
	e.BytesOut, e.BytesIn = splice(client, buf.Reader, upstream)
	p.log(e)
}

// splice copies both ways until either side closes, returning bytes sent
// client→upstream and upstream→client. Bytes the client sent early are in pre.
func splice(client net.Conn, pre *bufio.Reader, upstream net.Conn) (out, in int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out, _ = io.Copy(upstream, pre)
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			upstream.Close()
		}
	}()
	in, _ = io.Copy(client, upstream)
	client.Close()
	wg.Wait()
	upstream.Close()
	return out, in
}

// hopHeaders are connection-specific and never forwarded.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	e := Entry{Time: time.Now().UTC(), Method: r.Method}
	host, port, err := splitHostPort(r.URL.Host, 80)
	if err != nil {
		p.deny(w, e, "bad request target: "+err.Error())
		return
	}
	e.Host, e.Port = host, port
	var dialled string
	transport := &http.Transport{
		Proxy: nil, // never chain to another proxy
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, addr, unlisted, err := p.dial(ctx, host, port)
			dialled, e.Unlisted = addr, unlisted
			return c, err
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	counted := &countingReader{r: r.Body}
	out.Body = counted
	resp, err := transport.RoundTrip(out)
	e.Addr = dialled
	if err != nil {
		p.fail(w, e, err)
		return
	}
	defer resp.Body.Close()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	e.Allowed = true
	e.BytesIn, _ = io.Copy(w, resp.Body)
	e.BytesOut = counted.n
	p.log(e)
}

type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error {
	if c.r == nil {
		return nil
	}
	return c.r.Close()
}

// Summary aggregates a log for the inventory.
type Summary struct {
	Connections []Connection `json:"connections"`
	Denied      int          `json:"denied"`
	// Unlisted counts connections report mode let through that enforce
	// mode would have denied.
	Unlisted int `json:"unlisted,omitempty"`
}

type Connection struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Allowed  bool   `json:"allowed"`
	Unlisted bool   `json:"unlisted,omitempty"`
	Count    int    `json:"count"`
	BytesOut int64  `json:"bytesOut"`
	BytesIn  int64  `json:"bytesIn"`
	Reason   string `json:"reason,omitempty"` // first denial reason
}

// Summarize reads a JSON-lines log. A malformed line is an error: a log that
// can't be read completely can't vouch for what fetch reached.
func Summarize(r io.Reader) (*Summary, error) {
	s := &Summary{Connections: []Connection{}}
	idx := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("egress log line %d: %w", n, err)
		}
		key := fmt.Sprintf("%s:%d:%t", e.Host, e.Port, e.Allowed)
		i, ok := idx[key]
		if !ok {
			i = len(s.Connections)
			idx[key] = i
			s.Connections = append(s.Connections, Connection{Host: e.Host, Port: e.Port, Allowed: e.Allowed, Unlisted: e.Unlisted, Reason: e.Reason})
		}
		c := &s.Connections[i]
		c.Count++
		c.BytesOut += e.BytesOut
		c.BytesIn += e.BytesIn
		if !e.Allowed {
			s.Denied++
		}
		if e.Allowed && e.Unlisted {
			s.Unlisted++
		}
	}
	return s, sc.Err()
}

// ReadyLine is printed once the proxy is listening.
const ReadyLine = "onion-proxy ready"

// Serve listens on addr and proxies until the listener fails. It prints
// ReadyLine to ready once the socket is open, so callers never race it.
func Serve(addr string, p *Proxy, ready io.Writer) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Fprintf(ready, "%s on %s\n", ReadyLine, l.Addr())
	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return srv.Serve(l)
}

// Fetch network modes recorded in the inventory.
const (
	ModeNone         = "none"         // the manifest has no fetch step
	ModeUnrestricted = "unrestricted" // fetch ran with full network
	ModeAllowList    = "allow-list"   // fetch ran behind the egress proxy
	// ModeRecord: report mode. Fetch ran behind the proxy, which recorded
	// connections outside the allow-list instead of denying them.
	ModeRecord = "record"
)

// Record is what the inventory keeps about the fetch step's network.
type Record struct {
	Mode       string                `json:"mode"`
	Rules      []manifest.EgressRule `json:"rules,omitempty"`
	ProxyImage string                `json:"proxyImage,omitempty"`
	Summary    *Summary              `json:"summary,omitempty"`
}

// Check verifies that a record is consistent with the manifest it claims to
// describe and shows no undeclared traffic. A report-mode record may show
// traffic outside the allow-list: that is what it is for, and peel grades it.
func (r *Record) Check(m *manifest.Manifest) error {
	if r.Mode == ModeRecord {
		if m.Dependencies.Fetch == "" {
			return errors.New("manifest has no fetch step, but egress record says \"record\"")
		}
		if len(m.Dependencies.Egress) != len(r.Rules) || (len(r.Rules) > 0 && !sameRules(m.Dependencies.Egress, r.Rules)) {
			return errors.New("egress record's rules differ from the manifest's dependencies.egress")
		}
		if r.Summary == nil {
			return errors.New("egress record has no connection log summary")
		}
		return nil
	}
	switch {
	case m.Dependencies.Fetch == "":
		if r.Mode != ModeNone {
			return fmt.Errorf("manifest has no fetch step, but egress record says %q", r.Mode)
		}
		return nil
	case len(m.Dependencies.Egress) == 0:
		if r.Mode != ModeUnrestricted {
			return fmt.Errorf("manifest declares no egress allow-list, but egress record says %q", r.Mode)
		}
		return nil
	}
	if r.Mode != ModeAllowList {
		return fmt.Errorf("manifest declares an egress allow-list, but fetch ran %q", r.Mode)
	}
	want, _ := json.Marshal(m.Dependencies.Egress)
	got, _ := json.Marshal(r.Rules)
	if !bytes.Equal(want, got) {
		return errors.New("egress record's rules differ from the manifest's dependencies.egress")
	}
	if r.Summary == nil {
		return errors.New("egress record has no connection log summary")
	}
	return r.Summary.CheckAgainst(r.Rules)
}

func sameRules(a, b []manifest.EgressRule) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Proposed is an allow-list covering every connection fetch made, for a
// manifest's dependencies.egress.
func (s *Summary) Proposed() []manifest.EgressRule {
	seen := map[string]bool{}
	var out []manifest.EgressRule
	for _, c := range s.Connections {
		if !c.Allowed {
			continue
		}
		k := fmt.Sprintf("%s:%d", c.Host, c.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		r := manifest.EgressRule{Host: c.Host}
		if c.Port != 443 {
			r.Port = c.Port
		}
		out = append(out, r)
	}
	return out
}

// CheckAgainst requires no denials and every allowed connection to match a rule.
func (s *Summary) CheckAgainst(rules []manifest.EgressRule) error {
	var errs []error
	for _, c := range s.Connections {
		if !c.Allowed {
			errs = append(errs, fmt.Errorf("denied %s:%d: %s", c.Host, c.Port, c.Reason))
		} else if _, ok := Match(rules, c.Host, c.Port); !ok {
			errs = append(errs, fmt.Errorf("allowed connection to %s:%d matches no rule", c.Host, c.Port))
		}
	}
	if s.Denied > 0 && len(errs) == 0 {
		errs = append(errs, fmt.Errorf("%d denied attempt(s)", s.Denied))
	}
	return errors.Join(errs...)
}
