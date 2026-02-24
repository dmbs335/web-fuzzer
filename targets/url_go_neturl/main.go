// URL parser target — Go net/url.
//
// Parses URLs using Go's net/url.Parse() and outputs parsed
// components as JSON for differential comparison.
//
// Go's net/url follows RFC 3986 with some lenient extensions:
//   - Accepts many inputs that strict RFC parsers reject
//   - Percent-encoding preservation vs normalization
//   - Opaque URI support (scheme:opaque?query)
//   - Different host extraction from Python/Node parsers
//   - Relevant to Go-based proxies (Caddy, Traefik), microservices
//
// Modes:
//   One-shot:   url_go_neturl <file>
//   Persistent:  url_go_neturl --persistent  (binary protocol on stdin/stdout)
//
// Binary protocol (same as Java targets):
//   Request:  [4-byte BE length][UTF-8 data]
//   Response: [4-byte BE length][UTF-8 output][4-byte BE exit_code]

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

type URLComponents struct {
	Fragment string `json:"fragment"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Port     string `json:"port"`
	Query    string `json:"query"`
	Scheme   string `json:"scheme"`
	Userinfo string `json:"userinfo"`
}

func parseURL(data string) (string, int) {
	data = strings.TrimSpace(data)
	if data == "" {
		empty, _ := json.Marshal(URLComponents{})
		return string(empty), 1
	}

	parsed, err := url.Parse(data)
	if err != nil {
		empty, _ := json.Marshal(URLComponents{})
		return string(empty), 1
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

	// Normalize default ports to empty (match other parsers' convention)
	defaultPorts := map[string]string{
		"http": "80", "https": "443", "ftp": "21",
		"ws": "80", "wss": "443",
	}
	if dp, ok := defaultPorts[strings.ToLower(parsed.Scheme)]; ok && port == dp {
		port = ""
	}

	// Extract path
	path := parsed.Path
	// For opaque URIs (scheme:opaque), use Opaque field
	if path == "" && parsed.Opaque != "" {
		path = parsed.Opaque
	}

	// Extract query (without leading ?)
	query := parsed.RawQuery

	// Extract fragment
	fragment := parsed.Fragment

	result := URLComponents{
		Fragment: fragment,
		Host:     host,
		Path:     path,
		Port:     port,
		Query:    query,
		Scheme:   parsed.Scheme,
		Userinfo: userinfo,
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		empty, _ := json.Marshal(URLComponents{})
		return string(empty), 1
	}

	return string(jsonBytes), 0
}

func persistentMode() {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for {
		// Read 4-byte big-endian length
		var length int32
		err := binary.Read(reader, binary.BigEndian, &length)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
			break
		}

		// Read input data
		inputBytes := make([]byte, length)
		_, err = io.ReadFull(reader, inputBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read data error: %v\n", err)
			break
		}

		input := string(inputBytes)
		output, exitCode := parseURL(input)
		outBytes := []byte(output)

		// Write 4-byte big-endian length
		binary.Write(writer, binary.BigEndian, int32(len(outBytes)))
		// Write output data
		writer.Write(outBytes)
		// Write 4-byte big-endian exit code
		binary.Write(writer, binary.BigEndian, int32(exitCode))
		writer.Flush()
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--persistent" {
		persistentMode()
		return
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: url_go_neturl <file>")
		fmt.Fprintln(os.Stderr, "       url_go_neturl --persistent")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "IO error: %v\n", err)
		os.Exit(2)
	}

	output, exitCode := parseURL(string(data))
	fmt.Println(output)
	os.Exit(exitCode)
}
