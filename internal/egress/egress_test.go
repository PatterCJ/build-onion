package egress

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PatterCJ/build-onion/internal/manifest"
)

func TestMatch(t *testing.T) {
	rules := []manifest.EgressRule{
		{Host: "proxy.golang.org"},
		{Host: "*.example.com", Port: 8443},
		{Host: "plain.example.org", Port: 80},
	}
	cases := []struct {
		host string
		port int
		ok   bool
	}{
		{"proxy.golang.org", 443, true},
		{"proxy.golang.org", 80, false}, // port is part of the rule
		{"evil-proxy.golang.org", 443, false},
		{"proxy.golang.org.evil.com", 443, false},
		{"a.example.com", 8443, true},
		{"a.b.example.com", 8443, true},
		{"example.com", 8443, false}, // a wildcard never matches the apex
		{"badexample.com", 8443, false},
		{"plain.example.org", 80, true},
	}
	for _, tc := range cases {
		if _, ok := Match(rules, tc.host, tc.port); ok != tc.ok {
			t.Errorf("%s:%d => %v, want %v", tc.host, tc.port, ok, tc.ok)
		}
	}
}

func TestCheckAddr(t *testing.T) {
	public := manifest.EgressRule{Host: "a.example.com"}
	internal := manifest.EgressRule{Host: "store.acme.internal", Private: true}
	cases := []struct {
		addr         string
		public, priv bool // allowed for a public rule, for a private rule
	}{
		{"142.250.1.1", true, true},
		{"2607:f8b0::1", true, true},
		{"10.1.2.3", false, true},
		{"172.20.0.5", false, true},
		{"192.168.1.10", false, true},
		{"100.64.3.4", false, true},
		{"fd12::1", false, true},
		{"127.0.0.1", false, false},
		{"::1", false, false},
		{"::ffff:127.0.0.1", false, false}, // mapped loopback
		{"169.254.169.254", false, false},  // cloud metadata, even for private rules
		{"fe80::1", false, false},
		{"fd00:ec2::254", false, false}, // AWS IMDS over IPv6
		{"0.0.0.0", false, false},
		{"224.0.0.1", false, false},
		{"::", false, false},
	}
	for _, tc := range cases {
		a := netip.MustParseAddr(tc.addr)
		if got := CheckAddr(a, public) == nil; got != tc.public {
			t.Errorf("%s public rule: allowed=%v, want %v", tc.addr, got, tc.public)
		}
		if got := CheckAddr(a, internal) == nil; got != tc.priv {
			t.Errorf("%s private rule: allowed=%v, want %v", tc.addr, got, tc.priv)
		}
	}
}

// safeBuffer lets the test read the log while the proxy writes it.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func timeSleep() { time.Sleep(10 * time.Millisecond) }

// harness runs a proxy whose resolver maps test names to local listeners.
type harness struct {
	p     *Proxy
	proxy *httptest.Server
	log   *safeBuffer
	names map[string]netip.Addr
}

func newHarness(t *testing.T, rules []manifest.EgressRule, names map[string]string, allowLoopback bool) *harness {
	t.Helper()
	h := &harness{log: &safeBuffer{}, names: map[string]netip.Addr{}}
	for n, a := range names {
		h.names[n] = netip.MustParseAddr(a)
	}
	p := &Proxy{
		Rules: rules,
		Log:   h.log,
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if a, ok := h.names[host]; ok {
				return []netip.Addr{a}, nil
			}
			return nil, fmt.Errorf("no such host %s", host)
		},
	}
	if allowLoopback {
		// Local test servers live on loopback. Everything else about the
		// production check still applies.
		p.CheckAddr = func(a netip.Addr, r manifest.EgressRule) error {
			if a.IsLoopback() {
				return nil
			}
			return CheckAddr(a, r)
		}
	}
	h.p = p
	h.proxy = httptest.NewServer(p)
	t.Cleanup(h.proxy.Close)
	return h
}

func (h *harness) entries(t *testing.T) *Summary {
	t.Helper()
	s, err := Summarize(bytes.NewReader(h.log.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// connect sends a raw CONNECT and returns the status line and the conn.
func (h *harness) connect(t *testing.T, target string) (string, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(h.proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Status, c, br
}

// echoServer accepts one connection and echoes everything back.
func echoServer(t *testing.T) (port int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestConnectAllowedTunnels(t *testing.T) {
	port := echoServer(t)
	h := newHarness(t, []manifest.EgressRule{{Host: "mirror.example.com", Port: port}},
		map[string]string{"mirror.example.com": "127.0.0.1"}, true)

	status, c, br := h.connect(t, fmt.Sprintf("Mirror.Example.COM.:%d", port)) // case and trailing dot normalized
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("status %s", status)
	}
	fmt.Fprint(c, "hello")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	c.Close()

	s := waitForEntries(t, h, 1)
	if s.Denied != 0 || !s.Connections[0].Allowed || s.Connections[0].Host != "mirror.example.com" || s.Connections[0].BytesIn != 5 {
		t.Fatalf("summary = %+v", s)
	}
}

func TestConnectDenials(t *testing.T) {
	port := echoServer(t)
	rules := []manifest.EgressRule{
		{Host: "mirror.example.com", Port: port},
		{Host: "metadata.example.com", Port: port},
		{Host: "store.acme.internal", Port: port},
	}
	names := map[string]string{
		"mirror.example.com":   "127.0.0.1",
		"metadata.example.com": "169.254.169.254", // allowed name, forbidden address
		"store.acme.internal":  "10.0.0.8",        // private, but the rule doesn't say private: true
		"evil.example.net":     "127.0.0.1",
	}
	cases := map[string]string{
		"host not in the list":       fmt.Sprintf("evil.example.net:%d", port),
		"allowed host, wrong port":   "mirror.example.com:443",
		"allowed name → metadata IP": fmt.Sprintf("metadata.example.com:%d", port),
		"private without opt-in":     fmt.Sprintf("store.acme.internal:%d", port),
		"IP literal":                 fmt.Sprintf("127.0.0.1:%d", port),
		"IPv6 literal":               fmt.Sprintf("[::1]:%d", port),
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, rules, names, true)
			status, _, _ := h.connect(t, target)
			if !strings.HasPrefix(status, "403") {
				t.Fatalf("status %s", status)
			}
			if s := h.entries(t); s.Denied != 1 || s.Connections[0].Allowed {
				t.Fatalf("summary = %+v", s)
			}
		})
	}
}

func TestProductionCheckBlocksLoopback(t *testing.T) {
	// Without the test override, an allowed name that resolves to loopback
	// (a DNS rebinding attempt against the runner) is denied.
	port := echoServer(t)
	h := newHarness(t, []manifest.EgressRule{{Host: "mirror.example.com", Port: port}},
		map[string]string{"mirror.example.com": "127.0.0.1"}, false)
	status, _, _ := h.connect(t, fmt.Sprintf("mirror.example.com:%d", port))
	if !strings.HasPrefix(status, "403") {
		t.Fatalf("status %s", status)
	}
}

func TestUnreachableAllowedHostIsNotADenial(t *testing.T) {
	// Allowed by policy but nothing listening: a network failure (502), logged
	// as allowed, so it doesn't count against the allow-list.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	h := newHarness(t, []manifest.EgressRule{{Host: "down.example.com", Port: port}},
		map[string]string{"down.example.com": "127.0.0.1"}, true)
	status, _, _ := h.connect(t, fmt.Sprintf("down.example.com:%d", port))
	if !strings.HasPrefix(status, "502") {
		t.Fatalf("status %s", status)
	}
	if s := h.entries(t); s.Denied != 0 || !s.Connections[0].Allowed || s.Connections[0].Reason == "" {
		t.Fatalf("summary = %+v", s)
	}
}

func TestPlainHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("Proxy-Authorization forwarded upstream")
		}
		fmt.Fprint(w, "module data")
	}))
	defer upstream.Close()
	port := upstream.Listener.Addr().(*net.TCPAddr).Port
	h := newHarness(t, []manifest.EgressRule{{Host: "plain.example.com", Port: port}},
		map[string]string{"plain.example.com": "127.0.0.1", "other.example.com": "127.0.0.1"}, true)
	proxyURL, _ := url.Parse(h.proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://plain.example.com:%d/x", port), nil)
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "module data" {
		t.Fatalf("allowed: %d %q", resp.StatusCode, body)
	}

	resp, err = client.Get(fmt.Sprintf("http://other.example.com:%d/x", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("denied: status %d", resp.StatusCode)
	}
	s := h.entries(t)
	if s.Denied != 1 || len(s.Connections) != 2 {
		t.Fatalf("summary = %+v", s)
	}
}

func TestDirectRequestsRejected(t *testing.T) {
	h := newHarness(t, nil, nil, true)
	resp, err := http.Get(h.proxy.URL + "/anything")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestSummarizeRejectsCorruptLog(t *testing.T) {
	if _, err := Summarize(strings.NewReader("{\"host\":\"a\"}\nnot json\n")); err == nil {
		t.Fatal("corrupt log accepted")
	}
}

// waitForEntries polls until the tunnel's log entry is written (it's written
// after both directions close).
func waitForEntries(t *testing.T, h *harness, n int) *Summary {
	t.Helper()
	for i := 0; i < 200; i++ {
		s := h.entries(t)
		total := 0
		for _, c := range s.Connections {
			total += c.Count
		}
		if total >= n {
			return s
		}
		timeSleep()
	}
	t.Fatal("log entry never written")
	return nil
}

func TestIPLiteralDeniedEvenIfListed(t *testing.T) {
	// Manifest validation rejects IP rules, but the proxy doesn't rely on it:
	// a target given as an IP is refused before rules are consulted.
	port := echoServer(t)
	h := newHarness(t, []manifest.EgressRule{{Host: "127.0.0.1", Port: port}}, nil, true)
	status, _, _ := h.connect(t, fmt.Sprintf("127.0.0.1:%d", port))
	if !strings.HasPrefix(status, "403") {
		t.Fatalf("status %s", status)
	}
}

// Report mode lets a host outside the allow-list through, marked unlisted,
// and keeps every other protection: the address checks and the refusal of
// IP-address targets.
func TestReportMode(t *testing.T) {
	port := echoServer(t)
	names := map[string]string{"mirror.example.com": "127.0.0.1", "other.example.net": "127.0.0.1", "metadata.example.com": "169.254.169.254"}
	h := newHarness(t, []manifest.EgressRule{{Host: "mirror.example.com", Port: port}}, names, true)
	h.p.Report = true

	status, c, _ := h.connect(t, fmt.Sprintf("other.example.net:%d", port))
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("unlisted host: status %s", status)
	}
	c.Close()
	s := waitForEntries(t, h, 1)
	if s.Denied != 0 || s.Unlisted != 1 || !s.Connections[0].Allowed || !s.Connections[0].Unlisted {
		t.Fatalf("summary = %+v", s)
	}
	if p := s.Proposed(); len(p) != 1 || p[0].Host != "other.example.net" || p[0].Port != port {
		t.Errorf("proposed = %+v", p)
	}

	for name, target := range map[string]string{
		"metadata address": fmt.Sprintf("metadata.example.com:%d", port),
		"IP literal":       fmt.Sprintf("127.0.0.1:%d", port),
	} {
		h := newHarness(t, nil, names, true)
		h.p.Report = true
		if status, _, _ := h.connect(t, target); !strings.HasPrefix(status, "403") {
			t.Errorf("%s in report mode: status %s", name, status)
		}
	}
}

func TestRecordModeCheck(t *testing.T) {
	m := &manifest.Manifest{Dependencies: manifest.Dependencies{Fetch: "go mod download", Egress: []manifest.EgressRule{{Host: "proxy.golang.org"}}}}
	sum := &Summary{Connections: []Connection{{Host: "evil.example.net", Port: 443, Allowed: true, Unlisted: true, Count: 1}}, Unlisted: 1}
	rec := &Record{Mode: ModeRecord, Rules: m.Dependencies.Egress, Summary: sum}
	if err := rec.Check(m); err != nil {
		t.Errorf("a report-mode record with unlisted traffic is consistent: %v", err)
	}
	rec.Rules = nil
	if err := rec.Check(m); err == nil {
		t.Error("record with other rules accepted")
	}
	noRules := &manifest.Manifest{Dependencies: manifest.Dependencies{Fetch: "x"}}
	if err := (&Record{Mode: ModeRecord, Summary: sum}).Check(noRules); err != nil {
		t.Errorf("report mode without an allow-list: %v", err)
	}
	if err := (&Record{Mode: ModeRecord}).Check(noRules); err == nil {
		t.Error("record without a log accepted")
	}
}
