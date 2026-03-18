// OAuth redirect_uri + scope target — Go fosite (ory/fosite).
//
// Replicates fosite's redirect_uri matching and scope strategies:
//   - MatchRedirectURIWithClientRedirectURIs: Go net/url (RFC 3986) parsing
//   - Loopback port-agnostic matching for 127.0.0.1 and [::1] (RFC 8252)
//   - HierarchicScopeStrategy: dot-separated hierarchy matching
//   - ExactScopeStrategy: exact string match
//
// Go's net/url differs from WHATWG URL (Node):
//   - Preserves ports (no default port stripping)
//   - More lenient about relative URLs
//   - Different percent-encoding normalization
//
// Modes:
//   One-shot:   oauth_fosite <file>
//   Persistent: oauth_fosite --persistent  (binary protocol on stdin/stdout)

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

type OAuthInput struct {
	Type             string   `json:"type"`
	Registered       []string `json:"registered"`
	Candidate        string   `json:"candidate"`
	ApplicationType  string   `json:"application_type"`
	Granted          string   `json:"granted"`
	Requested        string   `json:"requested"`
	AuthRedirectURI  string   `json:"auth_redirect_uri"`
	TokenRedirectURI *string  `json:"token_redirect_uri"`
	GrantType        string   `json:"grant_type"`
	Code             string   `json:"code"`
}

type OAuthResult struct {
	InputType             string   `json:"input_type"`
	RedirectMatch         *bool    `json:"redirect_match"`
	RedirectMatchedIndex  *int     `json:"redirect_matched_index"`
	CandidateScheme       *string  `json:"candidate_scheme"`
	CandidateHost         *string  `json:"candidate_host"`
	CandidatePort         *string  `json:"candidate_port"`
	CandidatePath         *string  `json:"candidate_path"`
	CandidateNormalized   *string  `json:"candidate_normalized"`
	LoopbackDetected      *bool    `json:"loopback_detected"`
	FragmentPresent       *bool    `json:"fragment_present"`
	ScopeMatch            *bool    `json:"scope_match"`
	ScopeParsedGranted    []string `json:"scope_parsed_granted"`
	ScopeParsedRequested  []string `json:"scope_parsed_requested"`
	ScopeCountGranted     *int     `json:"scope_count_granted"`
	ScopeCountRequested   *int     `json:"scope_count_requested"`
	ScopeEmptyElements    *int     `json:"scope_empty_elements"`
}

var loopbacks = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"[::1]":     true,
	"::1":       true,
}

func boolPtr(v bool) *bool    { return &v }
func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }

func isLoopback(hostname string) bool {
	h := strings.ToLower(hostname)
	if loopbacks[h] {
		return true
	}
	// .localhost suffix (RFC 6761)
	if strings.HasSuffix(h, ".localhost") {
		return true
	}
	return false
}

// isValidRedirectURI checks that the URI is absolute and has no fragment.
func isValidRedirectURI(u *url.URL) bool {
	return u.IsAbs() && u.Fragment == ""
}

// matchRedirectURI replicates fosite's MatchRedirectURIWithClientRedirectURIs.
func matchRedirectURI(candidate string, registered []string, appType string) (matched bool, matchIdx *int, loopbackUsed bool) {
	// Exact string match first
	for i, reg := range registered {
		if candidate == reg {
			return true, intPtr(i), false
		}
	}

	// Loopback port-agnostic matching (RFC 8252)
	parsedCandidate, err := url.Parse(candidate)
	if err != nil {
		return false, nil, false
	}

	if parsedCandidate.Scheme == "http" && isLoopback(parsedCandidate.Hostname()) {
		loopbackUsed = true
		// Strip port from candidate
		candidateNoPort := *parsedCandidate
		candidateNoPort.Host = parsedCandidate.Hostname()

		for i, reg := range registered {
			parsedReg, err := url.Parse(reg)
			if err != nil {
				continue
			}
			regNoPort := *parsedReg
			regNoPort.Host = parsedReg.Hostname()
			if candidateNoPort.String() == regNoPort.String() {
				return true, intPtr(i), true
			}
		}
	}

	return false, nil, loopbackUsed
}

// hierarchicScopeMatch replicates fosite's HierarchicScopeStrategy.
// "foo.bar" in haystack matches needle "foo.bar.baz" (prefix match on dots).
func hierarchicScopeMatch(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
		// Check if haystack scope is a prefix of needle with dot separator
		if strings.HasPrefix(needle, h+".") {
			return true
		}
	}
	return false
}

func checkRedirectURI(input *OAuthInput) *OAuthResult {
	result := &OAuthResult{InputType: "redirect_uri"}

	candidate := input.Candidate
	registered := input.Registered
	if registered == nil {
		registered = []string{}
	}

	fragmentPresent := strings.Contains(candidate, "#")
	result.FragmentPresent = boolPtr(fragmentPresent)

	parsedCandidate, err := url.Parse(candidate)
	if err != nil || !parsedCandidate.IsAbs() {
		result.RedirectMatch = boolPtr(false)
		result.CandidateNormalized = strPtr(candidate)
		result.LoopbackDetected = boolPtr(false)
		return result
	}

	result.CandidateScheme = strPtr(parsedCandidate.Scheme)
	result.CandidateHost = strPtr(parsedCandidate.Hostname())
	port := parsedCandidate.Port()
	if port != "" {
		result.CandidatePort = strPtr(port)
	}
	result.CandidatePath = strPtr(parsedCandidate.Path)
	result.CandidateNormalized = strPtr(parsedCandidate.String())

	appType := input.ApplicationType
	if appType == "" {
		appType = "web"
	}

	matched, matchIdx, loopbackUsed := matchRedirectURI(candidate, registered, appType)
	result.RedirectMatch = boolPtr(matched)
	result.RedirectMatchedIndex = matchIdx
	result.LoopbackDetected = boolPtr(loopbackUsed)

	return result
}

func checkScope(input *OAuthInput) *OAuthResult {
	result := &OAuthResult{InputType: "scope"}

	granted := input.Granted
	requested := input.Requested

	// Split on space (like OAuth spec), but also track empties
	grantedParts := []string{}
	if granted != "" {
		grantedParts = strings.Split(granted, " ")
	}
	requestedParts := []string{}
	if requested != "" {
		requestedParts = strings.Split(requested, " ")
	}

	// Filter empty strings for matching
	grantedClean := []string{}
	emptyCount := 0
	for _, s := range grantedParts {
		if s == "" {
			emptyCount++
		} else {
			grantedClean = append(grantedClean, s)
		}
	}
	requestedClean := []string{}
	for _, s := range requestedParts {
		if s != "" {
			requestedClean = append(requestedClean, s)
		}
	}

	// Use hierarchic scope strategy (fosite's default)
	allMatch := true
	for _, req := range requestedClean {
		if !hierarchicScopeMatch(grantedClean, req) {
			allMatch = false
			break
		}
	}

	result.ScopeMatch = boolPtr(allMatch)
	result.ScopeParsedGranted = grantedParts
	result.ScopeParsedRequested = requestedParts
	grantedCount := len(grantedParts)
	requestedCount := len(requestedParts)
	result.ScopeCountGranted = intPtr(grantedCount)
	result.ScopeCountRequested = intPtr(requestedCount)
	result.ScopeEmptyElements = intPtr(emptyCount)

	return result
}

type TokenExchangeResult struct {
	InputType       string  `json:"input_type"`
	AuthMatch       bool    `json:"auth_match"`
	TokenMatch      bool    `json:"token_match"`
	URIIdentical    bool    `json:"uri_identical"`
	AuthNormalized  string  `json:"auth_normalized"`
	TokenNormalized *string `json:"token_normalized"`
	AuthHost        *string `json:"auth_host"`
	TokenHost       *string `json:"token_host"`
	AuthPort        *string `json:"auth_port"`
	TokenPort       *string `json:"token_port"`
}

func checkTokenExchange(input *OAuthInput) *TokenExchangeResult {
	registered := input.Registered
	if registered == nil {
		registered = []string{}
	}

	authURI := input.AuthRedirectURI
	result := &TokenExchangeResult{InputType: "token_exchange"}

	// Parse auth URI
	authParsed, authErr := url.Parse(authURI)
	if authErr == nil {
		result.AuthNormalized = authParsed.String()
		h := authParsed.Hostname()
		if h != "" {
			result.AuthHost = strPtr(h)
		}
		p := authParsed.Port()
		if p != "" {
			result.AuthPort = strPtr(p)
		}
	} else {
		result.AuthNormalized = authURI
	}

	// Check auth match against registered (exact string)
	for _, r := range registered {
		if authURI == r {
			result.AuthMatch = true
			break
		}
	}

	// Handle token_redirect_uri
	if input.TokenRedirectURI != nil {
		tokenURI := *input.TokenRedirectURI
		tokenParsed, tokenErr := url.Parse(tokenURI)
		if tokenErr == nil {
			norm := tokenParsed.String()
			result.TokenNormalized = strPtr(norm)
			h := tokenParsed.Hostname()
			if h != "" {
				result.TokenHost = strPtr(h)
			}
			p := tokenParsed.Port()
			if p != "" {
				result.TokenPort = strPtr(p)
			}
			// "identical" = parsed URL String() comparison
			if authErr == nil {
				result.URIIdentical = authParsed.String() == tokenParsed.String()
			}
		} else {
			norm := tokenURI
			result.TokenNormalized = &norm
		}
		// Check token match
		for _, r := range registered {
			if tokenURI == r {
				result.TokenMatch = true
				break
			}
		}
	}
	// If token_redirect_uri is nil: token_match=false, uri_identical=false, token_normalized=nil (defaults)

	return result
}

func processOAuth(inputStr string) (string, int) {
	var input OAuthInput
	if err := json.Unmarshal([]byte(inputStr), &input); err != nil {
		return "", 1
	}

	if input.Type == "" {
		return "", 1
	}

	var result *OAuthResult
	switch input.Type {
	case "redirect_uri":
		result = checkRedirectURI(&input)
	case "scope":
		result = checkScope(&input)
	case "token_exchange":
		te := checkTokenExchange(&input)
		out, err := json.Marshal(te)
		if err != nil {
			return "", 1
		}
		return string(out), 0
	default:
		result = &OAuthResult{InputType: input.Type}
	}

	out, err := json.Marshal(result)
	if err != nil {
		return "", 1
	}
	return string(out), 0
}

func persistentMode() {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for {
		var length int32
		err := binary.Read(reader, binary.BigEndian, &length)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
			break
		}

		inputBytes := make([]byte, length)
		if _, err := io.ReadFull(reader, inputBytes); err != nil {
			fmt.Fprintf(os.Stderr, "Read input error: %v\n", err)
			break
		}

		output, exitCode := processOAuth(string(inputBytes))
		outBytes := []byte(output)

		binary.Write(writer, binary.BigEndian, int32(len(outBytes)))
		writer.Write(outBytes)
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
		fmt.Fprintln(os.Stderr, "Usage: oauth_fosite <file>")
		fmt.Fprintln(os.Stderr, "       oauth_fosite --persistent")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
		os.Exit(2)
	}

	output, exitCode := processOAuth(string(data))
	if exitCode == 0 {
		fmt.Println(output)
	}
	os.Exit(exitCode)
}
