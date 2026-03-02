// SAML verification target — Go crewjam/saml + goxmldsig.
//
// Parses SAML Responses using Go's encoding/xml (via etree/goxmldsig)
// and verifies XML digital signatures. Outputs parsed components
// as JSON for differential comparison with other SAML libraries.
//
// Go's encoding/xml is fundamentally different from libxml2:
//   - Drops unknown namespace declarations
//   - Duplicate attributes: keeps last (libxml2 keeps first or errors)
//   - No XPointer support
//   - Rejects UTF-16 (libxml2 auto-detects)
//   - Limited namespace handling compared to libxml2
//
// Modes:
//   One-shot:   saml_crewjam <file>
//   Persistent: saml_crewjam --persistent  (binary protocol on stdin/stdout)

package main

import (
	"bufio"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type SAMLResult struct {
	SignatureValid bool              `json:"signature_valid"`
	SignatureError *string           `json:"signature_error"`
	Subject        *string           `json:"subject"`
	SubjectFormat  *string           `json:"subject_format"`
	Issuer         *string           `json:"issuer"`
	Audience       *string           `json:"audience"`
	Attributes     map[string]string `json:"attributes"`
	AssertionCount int               `json:"assertion_count"`
	AssertionID    *string           `json:"assertion_id"`
	Algorithms     map[string]string `json:"algorithms"`
}

var idpCert *x509.Certificate

func loadCert(certPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	idpCert = cert
	return nil
}

func shortenAlgo(uri string) string {
	parts := strings.Split(uri, "#")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	idx := strings.LastIndex(uri, "/")
	if idx >= 0 && idx < len(uri)-1 {
		return uri[idx+1:]
	}
	return uri
}

// findChildNS finds the first child element with matching namespace+tag.
func findChildNS(el *etree.Element, space, tag string) *etree.Element {
	for _, child := range el.ChildElements() {
		if child.Tag == tag && child.Space == space {
			return child
		}
		// Also try namespace URI match
		if child.Tag == tag {
			for _, attr := range child.Attr {
				if attr.Key == "xmlns" && attr.Value == space {
					return child
				}
			}
		}
	}
	// Fallback: match by tag only
	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}
	return nil
}

// findAllByTag recursively finds all elements with the given tag.
func findAllByTag(el *etree.Element, tag string) []*etree.Element {
	var results []*etree.Element
	if el.Tag == tag {
		results = append(results, el)
	}
	for _, child := range el.ChildElements() {
		results = append(results, findAllByTag(child, tag)...)
	}
	return results
}

// findSignedAssertion finds the assertion targeted by the signature's Reference URI.
// Falls back to the first assertion if no matching reference found.
func findSignedAssertion(root *etree.Element, assertions []*etree.Element) *etree.Element {
	for _, ref := range findAllByTag(root, "Reference") {
		uri := ref.SelectAttrValue("URI", "")
		if len(uri) > 1 && uri[0] == '#' {
			targetID := uri[1:]
			for _, a := range assertions {
				if a.SelectAttrValue("ID", "") == targetID {
					return a
				}
			}
		}
	}
	if len(assertions) > 0 {
		return assertions[0]
	}
	return nil
}

func verifySAML(xmlInput string) (string, int) {
	result := SAMLResult{
		Attributes: make(map[string]string),
		Algorithms: make(map[string]string),
	}

	// Parse with etree
	doc := etree.NewDocument()
	err := doc.ReadFromString(xmlInput)
	if err != nil {
		errStr := fmt.Sprintf("XML parse error: %v", err)
		result.SignatureError = &errStr
		out, _ := json.Marshal(result)
		return string(out), 1
	}

	root := doc.Root()
	if root == nil {
		errStr := "empty document"
		result.SignatureError = &errStr
		out, _ := json.Marshal(result)
		return string(out), 1
	}

	// Find all Assertion elements
	assertions := findAllByTag(root, "Assertion")
	result.AssertionCount = len(assertions)

	// Find the assertion targeted by the signature's Reference URI
	a := findSignedAssertion(root, assertions)

	// Extract fields from signed assertion
	if a != nil {
		if aid := a.SelectAttrValue("ID", ""); aid != "" {
			result.AssertionID = &aid
		}

		// Issuer
		issuerEl := findChildNS(a, "", "Issuer")
		if issuerEl != nil {
			v := issuerEl.Text()
			result.Issuer = &v
		} else {
			// Try Response-level Issuer
			respIssuer := findChildNS(root, "", "Issuer")
			if respIssuer != nil {
				v := respIssuer.Text()
				result.Issuer = &v
			}
		}

		// Subject/NameID
		subject := findChildNS(a, "", "Subject")
		if subject != nil {
			nameID := findChildNS(subject, "", "NameID")
			if nameID != nil {
				v := nameID.Text()
				result.Subject = &v
				format := nameID.SelectAttrValue("Format", "")
				if format != "" {
					result.SubjectFormat = &format
				}
			}
		}

		// Conditions/AudienceRestriction
		conditions := findChildNS(a, "", "Conditions")
		if conditions != nil {
			audRestrict := findChildNS(conditions, "", "AudienceRestriction")
			if audRestrict != nil {
				audience := findChildNS(audRestrict, "", "Audience")
				if audience != nil {
					v := audience.Text()
					result.Audience = &v
				}
			}
		}

		// Attributes
		for _, attrStmt := range findAllByTag(a, "AttributeStatement") {
			for _, attr := range findAllByTag(attrStmt, "Attribute") {
				name := attr.SelectAttrValue("Name", "")
				if name == "" {
					continue
				}
				attrVal := findChildNS(attr, "", "AttributeValue")
				if attrVal != nil {
					result.Attributes[name] = attrVal.Text()
				}
			}
		}

		// Extract algorithms from Signature
		var sigEl *etree.Element
		sigEl = findChildNS(a, "", "Signature")
		if sigEl == nil {
			sigEl = findChildNS(root, "", "Signature")
		}
		if sigEl != nil {
			signedInfo := findChildNS(sigEl, "", "SignedInfo")
			if signedInfo != nil {
				sigMethod := findChildNS(signedInfo, "", "SignatureMethod")
				if sigMethod != nil {
					result.Algorithms["signature"] = shortenAlgo(sigMethod.SelectAttrValue("Algorithm", ""))
				}
				ref := findChildNS(signedInfo, "", "Reference")
				if ref != nil {
					digestMethod := findChildNS(ref, "", "DigestMethod")
					if digestMethod != nil {
						result.Algorithms["digest"] = shortenAlgo(digestMethod.SelectAttrValue("Algorithm", ""))
					}
				}
			}
		}
	}

	// Signature verification using goxmldsig
	sigValid := false
	var sigErr string

	if idpCert != nil {
		certStore := &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idpCert},
		}
		ctx := dsig.NewDefaultValidationContext(certStore)

		// Find the Signature element to validate
		var sigElement *etree.Element
		// Look for Signature in assertions first, then response
		for _, a := range assertions {
			sigElement = findChildNS(a, "", "Signature")
			if sigElement != nil {
				break
			}
		}
		if sigElement == nil {
			sigElement = findChildNS(root, "", "Signature")
		}

		if sigElement == nil {
			sigErr = "no Signature element found"
		} else {
			_, validateErr := ctx.Validate(sigElement)
			if validateErr != nil {
				sigErr = fmt.Sprintf("%v", validateErr)
			} else {
				sigValid = true
			}
		}
	} else {
		sigErr = "no IdP certificate loaded"
	}

	result.SignatureValid = sigValid
	if sigErr != "" {
		result.SignatureError = &sigErr
	}

	out, _ := json.Marshal(result)
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
		_, err = io.ReadFull(reader, inputBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read data error: %v\n", err)
			break
		}

		output, exitCode := verifySAML(string(inputBytes))
		outBytes := []byte(output)

		binary.Write(writer, binary.BigEndian, int32(len(outBytes)))
		writer.Write(outBytes)
		binary.Write(writer, binary.BigEndian, int32(exitCode))
		writer.Flush()
	}
}

func main() {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	certPaths := []string{
		filepath.Join(exeDir, "..", "saml_fixtures", "idp_cert.pem"),
		filepath.Join("targets", "saml_fixtures", "idp_cert.pem"),
		filepath.Join("..", "saml_fixtures", "idp_cert.pem"),
	}

	for _, p := range certPaths {
		if err := loadCert(p); err == nil {
			break
		}
	}

	if len(os.Args) > 1 && os.Args[1] == "--persistent" {
		persistentMode()
		return
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: saml_crewjam <file>")
		fmt.Fprintln(os.Stderr, "       saml_crewjam --persistent")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "IO error: %v\n", err)
		os.Exit(2)
	}

	output, exitCode := verifySAML(string(data))
	fmt.Println(output)
	os.Exit(exitCode)
}
