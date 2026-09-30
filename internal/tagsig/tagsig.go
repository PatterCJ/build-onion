// Package tagsig verifies SSH-signed git tags against a set of allowed keys.
// A tag signed this way ties a release to a key held by a maintainer, which
// a stolen token can't produce.
//
// Signatures follow OpenSSH's SSHSIG format, as written by
// `git tag -s` with gpg.format=ssh.
package tagsig

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	beginSig  = "-----BEGIN SSH SIGNATURE-----"
	endSig    = "-----END SSH SIGNATURE-----"
	magic     = "SSHSIG"
	namespace = "git"
)

// Tag is a parsed, signature-verified annotated tag.
type Tag struct {
	Name   string // v1.0.0
	Object string // the tagged object's SHA
	Type   string // commit
	Tagger string
	// Key is the allowed key that signed it, in authorized_keys form.
	Key string
}

// Keys parses allowed signers in authorized_keys form ("ssh-ed25519 AAAA… comment").
func Keys(lines []string) ([]ssh.PublicKey, error) {
	var out []ssh.PublicKey
	for _, l := range lines {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			return nil, fmt.Errorf("signer key %q: %w", truncate(l), err)
		}
		out = append(out, k)
	}
	return out, nil
}

// Verify checks a raw tag object (the output of `git cat-file tag`) and
// returns it if one of the allowed keys signed it.
func Verify(raw []byte, allowed []ssh.PublicKey) (*Tag, error) {
	if len(allowed) == 0 {
		return nil, errors.New("no allowed signer keys")
	}
	i := bytes.Index(raw, []byte(beginSig))
	if i < 0 {
		return nil, errors.New("tag is not signed with an SSH key")
	}
	payload, armored := raw[:i], raw[i:]
	blob, err := unarmor(armored)
	if err != nil {
		return nil, err
	}
	key, err := verifySSHSIG(blob, payload, allowed)
	if err != nil {
		return nil, err
	}
	t, err := parseHeaders(payload)
	if err != nil {
		return nil, err
	}
	t.Key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	return t, nil
}

func unarmor(armored []byte) ([]byte, error) {
	s := strings.TrimSpace(string(armored))
	if !strings.HasPrefix(s, beginSig) || !strings.HasSuffix(s, endSig) {
		return nil, errors.New("malformed SSH signature block")
	}
	body := strings.Join(strings.Fields(s[len(beginSig):len(s)-len(endSig)]), "")
	return base64.StdEncoding.DecodeString(body)
}

// sshsig is the signature blob of PROTOCOL.sshsig.
type sshsig struct {
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

func verifySSHSIG(blob, message []byte, allowed []ssh.PublicKey) (ssh.PublicKey, error) {
	if !bytes.HasPrefix(blob, []byte(magic)) {
		return nil, errors.New("not an SSHSIG signature")
	}
	var sig sshsig
	if err := ssh.Unmarshal(blob[len(magic):], &sig); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if sig.Version != 1 {
		return nil, fmt.Errorf("unsupported SSHSIG version %d", sig.Version)
	}
	if sig.Namespace != namespace {
		return nil, fmt.Errorf("signature namespace %q, want %q", sig.Namespace, namespace)
	}
	key, err := ssh.ParsePublicKey(sig.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	var match ssh.PublicKey
	for _, a := range allowed {
		if bytes.Equal(a.Marshal(), key.Marshal()) {
			match = a
		}
	}
	if match == nil {
		return nil, fmt.Errorf("signed by %s, which is not an allowed signer", ssh.FingerprintSHA256(key))
	}
	var h []byte
	switch sig.HashAlg {
	case "sha256":
		s := sha256.Sum256(message)
		h = s[:]
	case "sha512":
		s := sha512.Sum512(message)
		h = s[:]
	default:
		return nil, fmt.Errorf("unsupported hash %q", sig.HashAlg)
	}
	signed := append([]byte(magic), ssh.Marshal(struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}{sig.Namespace, sig.Reserved, sig.HashAlg, h})...)
	var s ssh.Signature
	if err := ssh.Unmarshal(sig.Signature, &s); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if s.Format == ssh.KeyAlgoRSA {
		return nil, errors.New("ssh-rsa (SHA-1) signatures are not accepted")
	}
	if err := match.Verify(signed, &s); err != nil {
		return nil, fmt.Errorf("signature does not verify: %w", err)
	}
	return match, nil
}

var (
	headerRe = regexp.MustCompile(`^(object|type|tag|tagger) (.+)$`)
	objectRe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

func parseHeaders(payload []byte) (*Tag, error) {
	t := &Tag{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(payload), "\n") {
		if line == "" {
			break // headers end at the first blank line
		}
		m := headerRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("unexpected tag header %q", truncate(line))
		}
		if seen[m[1]] {
			return nil, fmt.Errorf("duplicate tag header %q", m[1])
		}
		seen[m[1]] = true
		switch m[1] {
		case "object":
			t.Object = m[2]
		case "type":
			t.Type = m[2]
		case "tag":
			t.Name = m[2]
		case "tagger":
			t.Tagger = m[2]
		}
	}
	if !objectRe.MatchString(t.Object) || t.Name == "" {
		return nil, errors.New("tag has no object or name")
	}
	return t, nil
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
