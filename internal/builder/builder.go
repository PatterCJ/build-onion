// Package builder runs a manifest's fetch and build steps in its pinned
// builder image. The pipeline's build and security lines and `onion peel
// --rebuild` all go through here, so there is exactly one definition of
// "the build".
package builder

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/egress"
	"github.com/PatterCJ/build-onion/internal/manifest"
)

// DefaultProxyImage runs the egress proxy: a minimal static image with no
// shell, pinned by digest. The proxy is the onion binary itself, mounted in.
const DefaultProxyImage = "gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"

type Runner struct {
	Docker string // container CLI; "docker" when empty
	Stdout io.Writer
	Stderr io.Writer
	// ProxyImage overrides DefaultProxyImage; it must be pinned by digest.
	ProxyImage string
	// Onion is the static onion binary mounted into the proxy container;
	// defaults to the running executable.
	Onion string
	// Report runs fetch behind the proxy in every case, recording hosts
	// outside the allow-list instead of denying them (policy mode: report).
	Report bool
	// NoInstallScripts turns off npm dependency install scripts for the
	// whole fetch step (npm_config_ignore_scripts=true, overriding the
	// manifest), whatever its command does (policy blockInstallScripts).
	NoInstallScripts bool
}

// fetchEnv is the fetch step's environment: the manifest's, plus what the
// policy enforces.
func (r Runner) fetchEnv(m *manifest.Manifest) map[string]string {
	env := map[string]string{}
	for k, v := range m.Dependencies.Env {
		if r.NoInstallScripts && strings.EqualFold(k, "npm_config_ignore_scripts") {
			continue
		}
		env[k] = v
	}
	if r.NoInstallScripts {
		env["npm_config_ignore_scripts"] = "true"
	}
	return env
}

func (r Runner) docker() string {
	if r.Docker == "" {
		return "docker"
	}
	return r.Docker
}

// Fetch populates cacheDir with dependencies. With an egress allow-list the
// fetch container's only route out is the filtering proxy, and any attempt to
// reach an undeclared host fails the fetch. Without one, fetch has
// unrestricted network, and the record says so.
func (r Runner) Fetch(srcDir, cacheDir string, m *manifest.Manifest) (*egress.Record, error) {
	if m.Dependencies.Fetch == "" {
		return &egress.Record{Mode: egress.ModeNone}, nil
	}
	var rec *egress.Record
	var err error
	if len(m.Dependencies.Egress) == 0 && !r.Report {
		err = r.run(srcDir, cacheDir, m, m.Dependencies.Fetch, []string{}, r.fetchEnv(m))
		rec = &egress.Record{Mode: egress.ModeUnrestricted}
	} else {
		rec, err = r.fetchRestricted(srcDir, cacheDir, m)
	}
	if rec != nil {
		rec.InstallScriptsDisabled = r.NoInstallScripts
	}
	return rec, err
}

// Build runs the build step with no network. Only srcDir and the fetched
// cache are visible to it.
func (r Runner) Build(srcDir, cacheDir string, m *manifest.Manifest) error {
	return r.run(srcDir, cacheDir, m, m.Build.Run, []string{"--network", "none"}, m.Build.Env)
}

func (r Runner) run(srcDir, cacheDir string, m *manifest.Manifest, script string, netArgs []string, env map[string]string) error {
	src, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}
	args := []string{"run", "--rm",
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"-v", src + ":/src", "-w", "/src",
		"-e", "HOME=/tmp",
	}
	args = append(args, netArgs...)
	if m.Dependencies.Cache != "" {
		cache, err := filepath.Abs(cacheDir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(cache, 0o755); err != nil {
			return err
		}
		args = append(args, "-v", cache+":"+m.Dependencies.Cache)
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+env[k])
	}
	args = append(args, m.Builder.Image, "sh", "-euc", script)

	cmd := exec.Command(r.docker(), args...)
	cmd.Stdout, cmd.Stderr = r.Stdout, r.Stderr
	if err := cmd.Run(); err != nil {
		step := "build"
		if script == m.Dependencies.Fetch {
			step = "fetch"
		}
		return fmt.Errorf("%s in %s: %w", step, m.Builder.Image, err)
	}
	return nil
}

// fetchRestricted runs fetch on an internal network whose only other member
// is the egress proxy:
//
//	fetch container ── onion-egress-in (internal, no route out) ── proxy ── onion-egress-out ── internet
//
// The fetch container gets HTTP(S)_PROXY pointing at the proxy; a tool that
// ignores those variables has no route anywhere. Its DNS upstream is set to
// an address with nothing listening, so external names can't be resolved (or
// used to smuggle data out) from inside it.
// proxyArgs runs `onion proxy` inside its container; report mode records
// hosts outside the allow-list instead of denying them.
func proxyArgs(report bool) []string {
	args := []string{"proxy", "--listen", "0.0.0.0:3128", "--rules", "/egress/rules.json", "--log", "/egress/egress.jsonl"}
	if report {
		args = append(args, "--report")
	}
	return args
}

func (r Runner) fetchRestricted(srcDir, cacheDir string, m *manifest.Manifest) (rec *egress.Record, err error) {
	proxyImage := r.ProxyImage
	if proxyImage == "" {
		proxyImage = DefaultProxyImage
	}
	if !manifest.IsPinnedImage(proxyImage) {
		return nil, fmt.Errorf("proxy image %q must be pinned by digest", proxyImage)
	}
	onion := r.Onion
	if onion == "" {
		if onion, err = os.Executable(); err != nil {
			return nil, err
		}
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	netIn, netOut, proxyName := "onion-egress-in-"+id, "onion-egress-out-"+id, "onion-proxy-"+id

	work, err := os.MkdirTemp("", "onion-egress-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	if err := os.Chmod(work, 0o755); err != nil {
		return nil, err
	}
	rules, err := json.Marshal(m.Dependencies.Egress)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(work, "rules.json"), rules, 0o644); err != nil {
		return nil, err
	}
	logPath := filepath.Join(work, "egress.jsonl")

	// Tear down in every case, including a failed setup.
	defer func() {
		r.quiet("rm", "-f", proxyName)
		r.quiet("network", "rm", netIn)
		r.quiet("network", "rm", netOut)
	}()
	if err := r.docker1("network", "create", netOut); err != nil {
		return nil, err
	}
	if err := r.docker1("network", "create", "--internal", netIn); err != nil {
		return nil, err
	}
	run := append([]string{"run", "-d", "--name", proxyName, "--network", netOut,
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"-v", onion + ":/onion:ro", "-v", work + ":/egress",
		"--entrypoint", "/onion", proxyImage,
	}, proxyArgs(r.Report)...)
	if err := r.docker1(run...); err != nil {
		return nil, err
	}
	if err := r.docker1("network", "connect", "--alias", "onion-proxy", netIn, proxyName); err != nil {
		return nil, err
	}
	if err := r.waitReady(proxyName); err != nil {
		return nil, err
	}

	env := r.fetchEnv(m)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env[k] = "http://onion-proxy:3128"
	}
	env["NO_PROXY"], env["no_proxy"] = "", ""
	fetchErr := r.run(srcDir, cacheDir, m, m.Dependencies.Fetch, []string{"--network", netIn, "--dns", "127.0.0.1"}, env)

	// Stop the proxy so every tunnel is closed and logged before reading.
	r.quiet("stop", "-t", "5", proxyName)
	f, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("egress log: %w", err)
	}
	summary, err := egress.Summarize(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	mode := egress.ModeAllowList
	if r.Report {
		mode = egress.ModeRecord
	}
	rec = &egress.Record{Mode: mode, Rules: m.Dependencies.Egress, ProxyImage: proxyImage, Summary: summary}
	if summary.Denied > 0 {
		var denied []string
		for _, c := range summary.Connections {
			if !c.Allowed {
				denied = append(denied, fmt.Sprintf("%s:%d (%s)", c.Host, c.Port, c.Reason))
			}
		}
		return rec, fmt.Errorf("fetch tried to reach %d undeclared or forbidden destination(s): %s; declare them in dependencies.egress or remove the dependency",
			summary.Denied, strings.Join(denied, ", "))
	}
	return rec, fetchErr
}

func (r Runner) docker1(args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(r.docker(), args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker %s: %v: %s", strings.Join(args[:min(3, len(args))], " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (r Runner) quiet(args ...string) { _ = exec.Command(r.docker(), args...).Run() }

func (r Runner) waitReady(name string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command(r.docker(), "logs", name).CombinedOutput()
		if bytes.Contains(out, []byte(egress.ReadyLine)) {
			return nil
		}
		running, _ := exec.Command(r.docker(), "inspect", "-f", "{{.State.Running}}", name).Output()
		if strings.TrimSpace(string(running)) == "false" {
			return fmt.Errorf("egress proxy exited: %s", strings.TrimSpace(string(out)))
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("egress proxy did not become ready in 30s")
}

func randomID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Collect copies each declared output file into outDir by basename and
// returns their digests.
func Collect(srcDir, outDir string, m *manifest.Manifest) (map[string]string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	digests := map[string]string{}
	for _, f := range m.Outputs.Files {
		raw, err := os.ReadFile(filepath.Join(srcDir, f))
		if err != nil {
			return nil, fmt.Errorf("declared output %s was not produced: %w", f, err)
		}
		name := filepath.Base(f)
		if err := os.WriteFile(filepath.Join(outDir, name), raw, 0o755); err != nil {
			return nil, err
		}
		digests[name] = digest.Bytes(raw)
	}
	return digests, nil
}
