// Bluemonday sanitizer differential target.
//
// Self-contained binary implementing the persistent wrapper protocol:
//   Request:  [4-byte BE length][input bytes]
//   Response: [4-byte BE length][output bytes][4-byte BE exit code]
//
// Also supports process mode: sanitizer_bluemonday.exe <input_file>
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/net/html"
)

var policy = bluemonday.UGCPolicy()

var (
	eventHandlerRE = regexp.MustCompile(`(?i)^on[a-z]`)
	jsURIRE        = regexp.MustCompile(`(?i)^\s*javascript\s*:`)
	dataHTMLRE     = regexp.MustCompile(`(?i)^\s*data\s*:\s*text/html`)
)

var uriAttrs = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true,
	"poster": true, "data": true, "codebase": true,
}

type result struct {
	Sanitized       string   `json:"sanitized"`
	ElementsKept    []string `json:"elements_kept"`
	AttributesKept  []string `json:"attributes_kept"`
	HasScript       bool     `json:"has_script"`
	HasEventHandler bool     `json:"has_event_handler"`
	HasJavascriptURI bool    `json:"has_javascript_uri"`
	HasDataURI      bool     `json:"has_data_uri"`
	HasSVG          bool     `json:"has_svg"`
	HasMath         bool     `json:"has_math"`
	HasStyle        bool     `json:"has_style"`
	HasForm         bool     `json:"has_form"`
	HasBase         bool     `json:"has_base"`
	HasIframe       bool     `json:"has_iframe"`
	HasObjectEmbed  bool     `json:"has_object_embed"`
	HasNoscript     bool     `json:"has_noscript"`
	EmptyOutput     bool     `json:"empty_output"`
	Error           *string  `json:"error"`
}

func buildResult(sanitized string) result {
	elements := map[string]bool{}
	attributes := map[string]bool{}
	hasScript := false
	hasEventHandler := false
	hasJavascriptURI := false
	hasDataURI := false

	doc, err := html.Parse(strings.NewReader(sanitized))
	if err == nil {
		var walk func(*html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode {
				tag := strings.ToLower(n.Data)
				if tag != "html" && tag != "head" && tag != "body" {
					elements[tag] = true
					if tag == "script" {
						hasScript = true
					}
				}
				for _, attr := range n.Attr {
					name := strings.ToLower(attr.Key)
					attributes[name] = true
					if eventHandlerRE.MatchString(name) {
						hasEventHandler = true
					}
					if uriAttrs[name] {
						if jsURIRE.MatchString(attr.Val) {
							hasJavascriptURI = true
						}
						if dataHTMLRE.MatchString(attr.Val) {
							hasDataURI = true
						}
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(doc)
	}

	elems := make([]string, 0, len(elements))
	for k := range elements {
		elems = append(elems, k)
	}
	sort.Strings(elems)

	attrs := make([]string, 0, len(attributes))
	for k := range attributes {
		attrs = append(attrs, k)
	}
	sort.Strings(attrs)

	truncated := sanitized
	if len(truncated) > 2000 {
		truncated = truncated[:2000]
	}

	return result{
		Sanitized:       truncated,
		ElementsKept:    elems,
		AttributesKept:  attrs,
		HasScript:       hasScript,
		HasEventHandler: hasEventHandler,
		HasJavascriptURI: hasJavascriptURI,
		HasDataURI:      hasDataURI,
		HasSVG:          elements["svg"],
		HasMath:         elements["math"],
		HasStyle:        elements["style"],
		HasForm:         elements["form"],
		HasBase:         elements["base"],
		HasIframe:       elements["iframe"],
		HasObjectEmbed:  elements["object"] || elements["embed"] || elements["applet"],
		HasNoscript:     elements["noscript"],
		EmptyOutput:     strings.TrimSpace(sanitized) == "",
		Error:           nil,
	}
}

func processInput(input string) ([]byte, int) {
	sanitized := policy.Sanitize(input)
	res := buildResult(sanitized)
	data, err := json.Marshal(res)
	if err != nil {
		errMsg := err.Error()
		errRes := result{EmptyOutput: true, Error: &errMsg, ElementsKept: []string{}, AttributesKept: []string{}}
		data, _ = json.Marshal(errRes)
		return data, 1
	}
	return data, 0
}

func persistentMode() {
	for {
		// Read 4-byte BE length
		var length uint32
		if err := binary.Read(os.Stdin, binary.BigEndian, &length); err != nil {
			if err == io.EOF {
				return
			}
			fmt.Fprintf(os.Stderr, "Read header error: %v\n", err)
			return
		}

		// Read input
		buf := make([]byte, length)
		if _, err := io.ReadFull(os.Stdin, buf); err != nil {
			return
		}

		output, exitCode := processInput(string(buf))

		// Write response: [4-byte len][output][4-byte exit code]
		binary.Write(os.Stdout, binary.BigEndian, uint32(len(output)))
		os.Stdout.Write(output)
		binary.Write(os.Stdout, binary.BigEndian, uint32(exitCode))
	}
}

func main() {
	if len(os.Args) >= 2 {
		// Process mode: read file
		data, err := os.ReadFile(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		output, exitCode := processInput(string(data))
		os.Stdout.Write(output)
		os.Exit(exitCode)
	}

	// No args: persistent mode
	persistentMode()
}
