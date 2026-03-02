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
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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

func parseURL(data string) (string, int) {
	data = strings.TrimSpace(data)
	if data == "" {
		empty, _ := json.Marshal(URLResult{})
		return string(empty), 1
	}

	parsed, err := url.Parse(data)
	if err != nil {
		empty, _ := json.Marshal(URLResult{})
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
		empty, _ := json.Marshal(URLResult{})
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

		output, exitCode := parseURL(string(inputBytes))
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
		fmt.Fprintf(os.Stderr, "Usage: url_go_net_url <file>\n")
		fmt.Fprintf(os.Stderr, "       url_go_net_url --persistent\n")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "IO error: %s\n", err)
		os.Exit(2)
	}

	output, exitCode := parseURL(string(data))
	fmt.Println(output)
	os.Exit(exitCode)
}
