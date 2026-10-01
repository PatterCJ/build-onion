package signer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const StatementType = "https://in-toto.io/Statement/v1"

// Subject is one artifact a statement is about.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto v1 statement.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NewStatement checks its parts and returns the statement's JSON.
func NewStatement(subjects []Subject, predicateType string, predicate []byte) ([]byte, error) {
	if len(subjects) == 0 {
		return nil, errors.New("a statement needs at least one subject")
	}
	if predicateType == "" {
		return nil, errors.New("predicate type is required")
	}
	if !json.Valid(predicate) || !bytes.HasPrefix(bytes.TrimSpace(predicate), []byte("{")) {
		return nil, errors.New("predicate must be a JSON object")
	}
	for _, s := range subjects {
		if s.Name == "" || !sha256Re.MatchString(s.Digest["sha256"]) {
			return nil, fmt.Errorf("subject %q needs a name and a sha256 digest", s.Name)
		}
	}
	return json.Marshal(Statement{Type: StatementType, Subject: subjects, PredicateType: predicateType, Predicate: predicate})
}

// SubjectsFromChecksums reads sha256sum output ("<hex>  <name>" per line).
func SubjectsFromChecksums(data []byte) ([]Subject, error) {
	var out []Subject
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sum, name, ok := strings.Cut(line, " ")
		name = strings.TrimPrefix(strings.TrimSpace(name), "*")
		if !ok || !sha256Re.MatchString(sum) || name == "" {
			return nil, fmt.Errorf("line %d: want \"<sha256>  <name>\"", n)
		}
		out = append(out, Subject{Name: name, Digest: map[string]string{"sha256": sum}})
	}
	return out, sc.Err()
}

// SubjectFromRef parses name@sha256:<hex>, as an image is named.
func SubjectFromRef(ref string) (Subject, error) {
	name, d, ok := strings.Cut(ref, "@sha256:")
	if !ok || name == "" || !sha256Re.MatchString(d) {
		return Subject{}, fmt.Errorf("%q: want name@sha256:<hex>", ref)
	}
	return Subject{Name: name, Digest: map[string]string{"sha256": d}}, nil
}
