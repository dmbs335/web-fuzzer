// JWT verification target — Go go-jose v4 + golang-jwt v5.
//
// Two verifiers selectable by command-line argument:
//   go_jose    — github.com/go-jose/go-jose/v4 (standard Go JOSE, used by Kubernetes)
//   golang_jwt — github.com/golang-jwt/jwt/v5 (most popular Go JWT lib)
//
// Modes:
//   One-shot:   jwt_go <go_jose|golang_jwt> <file>
//   Persistent: jwt_go <go_jose|golang_jwt> --persistent
//
// Output: standardized JSON matching Python/Node/Java JWT targets.

package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Same 6-byte secret as Python/Node targets — Go libs may or may not
// enforce minimum key size, and we WANT to discover that differential.
var hsSecret = []byte("secret")

// P-256 EC public key (same as all other JWT targets)
var ecPublicKeyDER = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX3+hdI8wUgMPJuIocOFdBxh+VZp6" +
	"GnlaqRqKGi1WSRcgg1+SLcoGu3XEP63c65tVW952Xw9lGiF5B3Q56sdssA=="

var ecPubKey *ecdsa.PublicKey

func init() {
	decoded, err := base64.StdEncoding.DecodeString(ecPublicKeyDER)
	if err != nil {
		panic("failed to decode EC public key: " + err.Error())
	}
	pub, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		panic("failed to parse EC public key: " + err.Error())
	}
	var ok bool
	ecPubKey, ok = pub.(*ecdsa.PublicKey)
	if !ok || ecPubKey.Curve != elliptic.P256() {
		panic("EC key is not P-256")
	}
}

// JWTResult is the standardized output matching other targets.
type JWTResult struct {
	SignatureValid   bool                `json:"signature_valid"`
	SignatureError   *string             `json:"signature_error"`
	HeaderAlg        string              `json:"header_alg"`
	EffectiveAlg     string              `json:"effective_alg"`
	KeySource        string              `json:"key_source"`
	ResolvedKID      *string             `json:"resolved_kid"`
	JWKSource        *string             `json:"jwk_source"`
	JKUSource        *string             `json:"jku_source"`
	X5USource        *string             `json:"x5u_source"`
	TokenTypeExpected string             `json:"token_type_expected"`
	TokenTypeObserved string             `json:"token_type_observed"`
	Typ              *string             `json:"typ"`
	Cty              *string             `json:"cty"`
	CritProcessed    *bool               `json:"crit_processed"`
	B64Mode          string              `json:"b64_mode"`
	DetachedPayload  bool                `json:"detached_payload_used"`
	Sub              interface{}         `json:"sub"`
	Iss              interface{}         `json:"iss"`
	Aud              interface{}         `json:"aud"`
	Role             interface{}         `json:"role"`
	Scope            interface{}         `json:"scope"`
	ClaimTypes       map[string]string   `json:"claim_types"`
	DupHeaderKeys    []string            `json:"duplicate_header_keys"`
	DupClaimKeys     []string            `json:"duplicate_claim_keys"`
	ClaimParseMode   string              `json:"claim_parse_mode"`
	TimeValid        bool                `json:"time_valid"`
	ExpState         string              `json:"exp_state"`
	NbfState         string              `json:"nbf_state"`
	IatState         string              `json:"iat_state"`
	NestedJWT        bool                `json:"nested_jwt"`
	InnerAlg         *string             `json:"inner_alg"`
	InnerSigValid    *bool               `json:"inner_signature_valid"`
}

func padBase64(s string) string {
	for len(s)%4 != 0 {
		s += "="
	}
	return s
}

func b64UrlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

var dupKeyRe = regexp.MustCompile(`"([^"]+)"\s*:`)

func findDuplicateKeys(jsonStr string) []string {
	seen := map[string]bool{}
	dupes := map[string]bool{}
	for _, m := range dupKeyRe.FindAllStringSubmatch(jsonStr, -1) {
		key := m[1]
		if seen[key] {
			dupes[key] = true
		}
		seen[key] = true
	}
	result := make([]string, 0, len(dupes))
	for k := range dupes {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

func claimType(v interface{}) string {
	switch vv := v.(type) {
	case float64:
		if math.Mod(vv, 1) == 0 {
			return "int"
		}
		return "float"
	case json.Number:
		if strings.Contains(vv.String(), ".") {
			return "float"
		}
		return "int"
	case string:
		return "str"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "dict"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func claimTypes(payload map[string]interface{}) map[string]string {
	out := map[string]string{}
	for _, key := range []string{"sub", "iss", "aud", "role", "scope", "exp", "nbf", "iat"} {
		if v, ok := payload[key]; ok && v != nil {
			out[key] = claimType(v)
		}
	}
	return out
}

func parsePreHeader(raw string) (headerMap map[string]interface{}, headerJSON string, parts []string) {
	parts = strings.Split(raw, ".")
	headerMap = map[string]interface{}{}
	if len(parts) >= 1 {
		if decoded, err := b64UrlDecode(parts[0]); err == nil {
			headerJSON = string(decoded)
			json.Unmarshal(decoded, &headerMap)
		}
	}
	return
}

func parsePrePayload(raw string) (payloadMap map[string]interface{}, payloadJSON string) {
	parts := strings.Split(raw, ".")
	payloadMap = map[string]interface{}{}
	if len(parts) >= 2 {
		if decoded, err := b64UrlDecode(parts[1]); err == nil {
			payloadJSON = string(decoded)
			// Use json.Number for numeric fidelity
			dec := json.NewDecoder(strings.NewReader(payloadJSON))
			dec.UseNumber()
			dec.Decode(&payloadMap)
		}
	}
	return
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func buildBaseResult(raw string) JWTResult {
	headerMap, headerJSON, parts := parsePreHeader(raw)
	payloadMap, payloadJSON := parsePrePayload(raw)

	tokenType := "unknown"
	switch len(parts) {
	case 3:
		tokenType = "jws"
	case 5:
		tokenType = "jwe"
	}

	alg, _ := headerMap["alg"].(string)
	var typ, cty *string
	if v, ok := headerMap["typ"].(string); ok {
		typ = &v
	}
	if v, ok := headerMap["cty"].(string); ok {
		cty = &v
	}

	keySource := "configured"
	if _, ok := headerMap["jku"]; ok {
		keySource = "jku"
	} else if _, ok := headerMap["jwk"]; ok {
		keySource = "embedded_jwk"
	} else if _, ok := headerMap["x5u"]; ok {
		keySource = "x5u"
	} else if _, ok := headerMap["x5c"]; ok {
		keySource = "x5c"
	}

	var kid *string
	if v, ok := headerMap["kid"].(string); ok {
		kid = &v
	}
	var jwkSource *string
	if _, ok := headerMap["jwk"]; ok {
		jwkSource = strPtr("embedded")
	}
	var jkuSource *string
	if v, ok := headerMap["jku"].(string); ok {
		jkuSource = &v
	}
	var x5uSource *string
	if v, ok := headerMap["x5u"].(string); ok {
		x5uSource = &v
	}

	var critProcessed *bool
	if _, ok := headerMap["crit"]; ok {
		critProcessed = boolPtr(false)
	}

	b64Mode := "normal"
	if v, ok := headerMap["b64"]; ok {
		if b, ok2 := v.(bool); ok2 && !b {
			b64Mode = "unencoded"
		}
	}

	dupHeader := findDuplicateKeys(headerJSON)
	dupClaims := findDuplicateKeys(payloadJSON)

	expState := "missing"
	if _, ok := payloadMap["exp"]; ok {
		expState = "valid"
	}
	nbfState := "missing"
	if _, ok := payloadMap["nbf"]; ok {
		nbfState = "valid"
	}
	iatState := "missing"
	if _, ok := payloadMap["iat"]; ok {
		iatState = "valid"
	}

	nested := false
	if cty != nil && strings.EqualFold(*cty, "JWT") {
		nested = true
	}
	if _, ok := payloadMap["nested"]; ok {
		nested = true
	}

	return JWTResult{
		SignatureValid:    false,
		HeaderAlg:         alg,
		EffectiveAlg:      alg,
		KeySource:         keySource,
		ResolvedKID:       kid,
		JWKSource:         jwkSource,
		JKUSource:         jkuSource,
		X5USource:         x5uSource,
		TokenTypeExpected: "jws",
		TokenTypeObserved: tokenType,
		Typ:               typ,
		Cty:               cty,
		CritProcessed:     critProcessed,
		B64Mode:           b64Mode,
		Sub:               payloadMap["sub"],
		Iss:               payloadMap["iss"],
		Aud:               payloadMap["aud"],
		Role:              payloadMap["role"],
		Scope:             payloadMap["scope"],
		ClaimTypes:        claimTypes(payloadMap),
		DupHeaderKeys:     dupHeader,
		DupClaimKeys:      dupClaims,
		ClaimParseMode:    "last_wins",
		TimeValid:         true,
		ExpState:          expState,
		NbfState:          nbfState,
		IatState:          iatState,
		NestedJWT:         nested,
	}
}

// ─── go-jose v4 verifier ───────────────────────────────────────

func verifyGoJose(tokenInput string) (string, int) {
	raw := strings.TrimSpace(tokenInput)
	result := buildBaseResult(raw)

	parts := strings.Split(raw, ".")
	if len(parts) < 3 {
		e := "JWT must contain at least 3 parts"
		result.SignatureError = &e
		out, _ := json.Marshal(result)
		return string(out), 1
	}

	// go-jose requires explicit algorithm list — good security practice
	allowedAlgs := []jose.SignatureAlgorithm{
		jose.HS256, jose.HS384, jose.HS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	}

	tok, err := josejwt.ParseSigned(raw, allowedAlgs)
	if err != nil {
		e := fmt.Sprintf("ParseSigned: %v", err)
		result.SignatureError = &e
		out, _ := json.Marshal(result)
		return string(out), 1
	}

	// Detect crit
	if len(tok.Headers) > 0 {
		h := tok.Headers[0]
		if len(h.ExtraHeaders) > 0 {
			if crit, ok := h.ExtraHeaders["crit"]; ok && crit != nil {
				result.CritProcessed = boolPtr(true)
			}
		}
	}

	// Try HMAC first, then EC
	claims := make(map[string]interface{})
	verified := false

	// Try with 6-byte secret
	err = tok.Claims(hsSecret, &claims)
	if err == nil {
		verified = true
	}

	if !verified {
		// Try with 32-byte padded secret (for interop with Java nimbus)
		paddedSecret := make([]byte, 32)
		copy(paddedSecret, hsSecret)
		claims = make(map[string]interface{})
		err = tok.Claims(paddedSecret, &claims)
		if err == nil {
			verified = true
		}
	}

	if !verified {
		// Try EC
		claims = make(map[string]interface{})
		err = tok.Claims(ecPubKey, &claims)
		if err == nil {
			verified = true
		}
	}

	if verified {
		result.SignatureValid = true
		// Update claims from verified token
		result.Sub = claims["sub"]
		result.Iss = claims["iss"]
		result.Aud = claims["aud"]
		result.Role = claims["role"]
		result.Scope = claims["scope"]
		result.ClaimTypes = claimTypes(claims)
		if _, ok := claims["exp"]; ok {
			result.ExpState = "valid"
		}
		if _, ok := claims["nbf"]; ok {
			result.NbfState = "valid"
		}
		if _, ok := claims["iat"]; ok {
			result.IatState = "valid"
		}
	} else {
		e := fmt.Sprintf("verification failed: %v", err)
		result.SignatureError = &e
	}

	out, _ := json.Marshal(result)
	return string(out), 0
}

// ─── golang-jwt v5 verifier ────────────────────────────────────

func verifyGolangJwt(tokenInput string) (string, int) {
	raw := strings.TrimSpace(tokenInput)
	result := buildBaseResult(raw)

	parts := strings.Split(raw, ".")
	if len(parts) < 3 {
		e := "JWT must contain at least 3 parts"
		result.SignatureError = &e
		out, _ := json.Marshal(result)
		return string(out), 1
	}

	// Use maximum leeway to effectively disable time validation
	parser := jwtv5.NewParser(
		jwtv5.WithLeeway(time.Duration(math.MaxInt64)),
		jwtv5.WithoutClaimsValidation(),
	)

	token, err := parser.Parse(raw, func(token *jwtv5.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwtv5.SigningMethodHMAC:
			return hsSecret, nil
		case *jwtv5.SigningMethodECDSA:
			return ecPubKey, nil
		case *jwtv5.SigningMethodRSA, *jwtv5.SigningMethodRSAPSS:
			// No RSA private key configured — return error to trigger differential
			return nil, fmt.Errorf("RSA key not configured")
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil {
		e := fmt.Sprintf("Parse: %v", err)
		result.SignatureError = &e

		// golang-jwt may still populate the token even on error
		if token != nil && token.Claims != nil {
			if mc, ok := token.Claims.(jwtv5.MapClaims); ok {
				result.Sub = mc["sub"]
				result.Iss = mc["iss"]
				result.Aud = mc["aud"]
				result.Role = mc["role"]
				result.Scope = mc["scope"]
				result.ClaimTypes = claimTypes(mc)
			}
		}

		out, _ := json.Marshal(result)
		return string(out), 0
	}

	result.SignatureValid = true

	// Detect crit header
	if crit, ok := token.Header["crit"]; ok && crit != nil {
		// golang-jwt does NOT process crit — it just ignores it
		result.CritProcessed = boolPtr(false)
	}

	if mc, ok := token.Claims.(jwtv5.MapClaims); ok {
		result.Sub = mc["sub"]
		result.Iss = mc["iss"]
		result.Aud = mc["aud"]
		result.Role = mc["role"]
		result.Scope = mc["scope"]
		result.ClaimTypes = claimTypes(mc)
		if _, ok := mc["exp"]; ok {
			result.ExpState = "valid"
		}
		if _, ok := mc["nbf"]; ok {
			result.NbfState = "valid"
		}
		if _, ok := mc["iat"]; ok {
			result.IatState = "valid"
		}
	}

	out, _ := json.Marshal(result)
	return string(out), 0
}

// ─── Persistent mode ───────────────────────────────────────────

func persistentMode(verifyFunc func(string) (string, int)) {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for {
		var length int32
		err := binary.Read(reader, binary.BigEndian, &length)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read length error: %v\n", err)
			break
		}

		inputBytes := make([]byte, length)
		_, err = io.ReadFull(reader, inputBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read data error: %v\n", err)
			break
		}

		output, exitCode := verifyFunc(string(inputBytes))
		outBytes := []byte(output)

		binary.Write(writer, binary.BigEndian, int32(len(outBytes)))
		writer.Write(outBytes)
		binary.Write(writer, binary.BigEndian, int32(exitCode))
		writer.Flush()
	}
}

// ─── Main ──────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: jwt_go <go_jose|golang_jwt> [--persistent] <input_file>")
		os.Exit(2)
	}

	verifierName := os.Args[1]
	var verifyFunc func(string) (string, int)

	switch verifierName {
	case "go_jose":
		verifyFunc = verifyGoJose
	case "golang_jwt":
		verifyFunc = verifyGolangJwt
	default:
		fmt.Fprintf(os.Stderr, "Unknown verifier: %s (use go_jose or golang_jwt)\n", verifierName)
		os.Exit(2)
	}

	remaining := os.Args[2:]

	if len(remaining) > 0 && remaining[0] == "--persistent" {
		persistentMode(verifyFunc)
		return
	}

	if len(remaining) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: jwt_go %s [--persistent] <input_file>\n", verifierName)
		os.Exit(2)
	}

	data, err := os.ReadFile(remaining[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "IO error: %v\n", err)
		os.Exit(2)
	}

	output, exitCode := verifyFunc(string(data))
	fmt.Println(output)
	os.Exit(exitCode)
}

