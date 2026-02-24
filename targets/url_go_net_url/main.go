// URL parser target — Go net/url.
//
// Parses URLs using Go's net/url.Parse() and outputs parsed
// components as JSON for differential comparison.
//
// Go's url.Parse() has notable differences:
//   - Supports opaque URIs (scheme:opaque) differently
//   - Strict RFC 3986 compliance in some areas
//   - Different handling of escaped characters
//   - Opaque vs hierarchical URI distinction
//   - Fragment handling differs from browser parsers
//
// References:
//   - Go net/url package docs
//   - RFC 3986 (Uniform Resource Identifier)

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type URLResult struct {
	Scheme   string `json:"scheme"`
	Userinfo string `json:"userinfo"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	Fragment string `json:"fragment"`
}

func parseURL(data string) (string, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return "", fmt.Errorf("empty input")
	}

	parsed, err := url.Parse(data)
	if err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}

	// Extract userinfo
	userinfo := ""
	if parsed.User != nil {
		userinfo = parsed.User.Username()
		if pw, ok := parsed.User.Password(); ok {
			userinfo += ":" + pw
		}
	}

	// Extract host and port
	host := parsed.Hostname()
	port := parsed.Port()

	// Extract path - for opaque URIs, use Opaque
	path := parsed.Path
	if path == "" && parsed.Opaque != "" {
		path = parsed.Opaque
	}

	// Extract query without leading ?
	query := parsed.RawQuery

	// Extract fragment
	fragment := parsed.Fragment

	result := URLResult{
		Scheme:   parsed.Scheme,
		Userinfo: userinfo,
		Host:     host,
		Port:     port,
		Path:     path,
		Query:    query,
		Fragment: fragment,
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("json marshal error: %w", err)
	}

	return string(jsonBytes), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: url_go_net_url <file>\n")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "IO error: %s\n", err)
		os.Exit(2)
	}

	result, err := parseURL(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "REJECT: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(result)
	os.Exit(0)
}
