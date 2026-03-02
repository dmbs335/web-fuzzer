/**
 * SAML signature verification target using JDK built-in javax.xml.crypto.
 *
 * Parser: Xerces (JDK built-in) - different from libxml2 (Python/Ruby) and
 * Go's encoding/xml. No external dependencies required.
 *
 * Usage:
 *   java SamlJavaXmldsig <file>          # one-shot mode
 *   java SamlJavaXmldsig --persistent    # persistent binary protocol
 */

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;
import org.xml.sax.InputSource;

public class SamlJavaXmldsig {

    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    private static X509Certificate idpCert;

    static {
        try {
            String certPath = System.getProperty("idp.cert",
                "targets/saml_fixtures/idp_cert.pem");
            byte[] certBytes = Files.readAllBytes(Paths.get(certPath));
            // Strip PEM header/footer
            String pem = new String(certBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(pem);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            idpCert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(der));
        } catch (Exception e) {
            System.err.println("Failed to load IdP cert: " + e.getMessage());
            System.exit(2);
        }
    }

    static String verifySaml(String xml) {
        boolean sigValid = false;
        String sigError = null;
        String subject = null;
        String subjectFormat = null;
        String issuer = null;
        String audience = null;
        int assertionCount = 0;
        String sigAlgo = "";
        String digestAlgo = "";
        Map<String, String> attributes = new TreeMap<>();

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            // Security: disable external entities
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xml)));

            // Count assertions
            NodeList assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
            assertionCount = assertions.getLength();

            // Find Signature
            NodeList sigs = doc.getElementsByTagNameNS(DS_NS, "Signature");
            if (sigs.getLength() > 0) {
                Element sigElem = (Element) sigs.item(0);

                // Extract algorithms
                NodeList sigMethods = sigElem.getElementsByTagNameNS(DS_NS, "SignatureMethod");
                if (sigMethods.getLength() > 0) {
                    sigAlgo = normalizeAlgo(
                        ((Element) sigMethods.item(0)).getAttribute("Algorithm"));
                }
                NodeList digestMethods = sigElem.getElementsByTagNameNS(DS_NS, "DigestMethod");
                if (digestMethods.getLength() > 0) {
                    digestAlgo = normalizeAlgo(
                        ((Element) digestMethods.item(0)).getAttribute("Algorithm"));
                }

                // Validate signature
                try {
                    DOMValidateContext valCtx = new DOMValidateContext(
                        idpCert.getPublicKey(), sigElem);
                    // Register ID attributes on Assertion and Response elements
                    registerIds(doc, valCtx);

                    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
                    XMLSignature signature = fac.unmarshalXMLSignature(valCtx);
                    sigValid = signature.validate(valCtx);
                    if (!sigValid) {
                        sigError = "Signature validation returned false";
                        // Check core validation
                        boolean sv = signature.getSignatureValue().validate(valCtx);
                        if (!sv) {
                            sigError = "SignatureValue validation failed";
                        } else {
                            // Check individual references
                            for (Object ref : signature.getSignedInfo().getReferences()) {
                                Reference r = (Reference) ref;
                                if (!r.validate(valCtx)) {
                                    sigError = "Reference validation failed: " + r.getURI();
                                    break;
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    sigValid = false;
                    sigError = e.getClass().getSimpleName() + ": " + e.getMessage();
                }
            } else {
                sigError = "No Signature element found";
            }

            // Extract assertion content from the signed assertion
            // (resolve via Reference URI to avoid XSW extraction confusion)
            Element assertion = findSignedAssertion(doc, assertions);
            String assertionId = null;
            if (assertion != null) {
                String aid = assertion.getAttribute("ID");
                if (aid != null && !aid.isEmpty()) assertionId = aid;

                // Issuer
                NodeList issuers = assertion.getElementsByTagNameNS(SAML_NS, "Issuer");
                if (issuers.getLength() > 0) {
                    issuer = issuers.item(0).getTextContent().trim();
                }

                // Subject/NameID
                NodeList nameIds = assertion.getElementsByTagNameNS(SAML_NS, "NameID");
                if (nameIds.getLength() > 0) {
                    Element nameId = (Element) nameIds.item(0);
                    subject = nameId.getTextContent().trim();
                    subjectFormat = nameId.getAttribute("Format");
                    if (subjectFormat.isEmpty()) subjectFormat = null;
                }

                // Audience
                NodeList audiences = assertion.getElementsByTagNameNS(SAML_NS, "Audience");
                if (audiences.getLength() > 0) {
                    audience = audiences.item(0).getTextContent().trim();
                }

                // Attributes
                NodeList attrStmts = assertion.getElementsByTagNameNS(
                    SAML_NS, "AttributeStatement");
                if (attrStmts.getLength() > 0) {
                    NodeList attrs = ((Element) attrStmts.item(0))
                        .getElementsByTagNameNS(SAML_NS, "Attribute");
                    for (int i = 0; i < attrs.getLength(); i++) {
                        Element attr = (Element) attrs.item(i);
                        String name = attr.getAttribute("Name");
                        NodeList vals = attr.getElementsByTagNameNS(
                            SAML_NS, "AttributeValue");
                        if (vals.getLength() > 0) {
                            attributes.put(name, vals.item(0).getTextContent().trim());
                        }
                    }
                }
            }
        } catch (Exception e) {
            sigError = "Parse error: " + e.getMessage();
        }

        // Build JSON output
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"algorithms\":{");
        sb.append("\"digest\":").append(jsonString(digestAlgo)).append(",");
        sb.append("\"signature\":").append(jsonString(sigAlgo));
        sb.append("},");
        sb.append("\"assertion_count\":").append(assertionCount).append(",");
        sb.append("\"assertion_id\":").append(jsonStringOrNull(assertionId)).append(",");
        sb.append("\"attributes\":{");
        boolean first = true;
        for (Map.Entry<String, String> e : attributes.entrySet()) {
            if (!first) sb.append(",");
            sb.append(jsonString(e.getKey())).append(":").append(jsonString(e.getValue()));
            first = false;
        }
        sb.append("},");
        sb.append("\"audience\":").append(jsonStringOrNull(audience)).append(",");
        sb.append("\"issuer\":").append(jsonStringOrNull(issuer)).append(",");
        sb.append("\"signature_error\":").append(jsonStringOrNull(sigError)).append(",");
        sb.append("\"signature_valid\":").append(sigValid).append(",");
        sb.append("\"subject\":").append(jsonStringOrNull(subject)).append(",");
        sb.append("\"subject_format\":").append(jsonStringOrNull(subjectFormat));
        sb.append("}");

        return sb.toString();
    }

    static void registerIds(Document doc, DOMValidateContext ctx) {
        // Register ID attributes on Assertion and Response elements
        NodeList assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
        for (int i = 0; i < assertions.getLength(); i++) {
            Element e = (Element) assertions.item(i);
            if (e.hasAttribute("ID")) {
                ctx.setIdAttributeNS(e, null, "ID");
            }
        }
        NodeList responses = doc.getElementsByTagNameNS(SAMLP_NS, "Response");
        for (int i = 0; i < responses.getLength(); i++) {
            Element e = (Element) responses.item(i);
            if (e.hasAttribute("ID")) {
                ctx.setIdAttributeNS(e, null, "ID");
            }
        }
    }

    static Element findSignedAssertion(Document doc, NodeList assertions) {
        // Find the assertion targeted by the Signature's Reference URI
        NodeList refs = doc.getElementsByTagNameNS(DS_NS, "Reference");
        for (int i = 0; i < refs.getLength(); i++) {
            String uri = ((Element) refs.item(i)).getAttribute("URI");
            if (uri != null && uri.startsWith("#")) {
                String targetId = uri.substring(1);
                for (int j = 0; j < assertions.getLength(); j++) {
                    Element a = (Element) assertions.item(j);
                    if (targetId.equals(a.getAttribute("ID"))) {
                        return a;
                    }
                }
            }
        }
        // Fallback: assertion that contains the Signature element
        NodeList sigs = doc.getElementsByTagNameNS(DS_NS, "Signature");
        if (sigs.getLength() > 0) {
            Node parent = sigs.item(0).getParentNode();
            if (parent instanceof Element) {
                Element pe = (Element) parent;
                if ("Assertion".equals(pe.getLocalName())) {
                    return pe;
                }
            }
        }
        // Last resort: first assertion
        return assertions.getLength() > 0 ? (Element) assertions.item(0) : null;
    }

    static String normalizeAlgo(String uri) {
        if (uri == null || uri.isEmpty()) return "";
        int idx = uri.lastIndexOf('#');
        if (idx >= 0) return uri.substring(idx + 1);
        idx = uri.lastIndexOf('/');
        if (idx >= 0) return uri.substring(idx + 1);
        return uri;
    }

    static String jsonString(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    static String jsonStringOrNull(String s) {
        return s == null ? "null" : jsonString(s);
    }

    // --- Persistent mode: binary protocol ---
    static void persistentMode() throws IOException {
        DataInputStream din = new DataInputStream(
            new BufferedInputStream(System.in));
        DataOutputStream dout = new DataOutputStream(
            new BufferedOutputStream(System.out));

        while (true) {
            int length;
            try {
                length = din.readInt();
            } catch (EOFException e) {
                break;
            }

            byte[] inputBytes = new byte[length];
            din.readFully(inputBytes);
            String input = new String(inputBytes, StandardCharsets.UTF_8);

            String output;
            int exitCode;
            try {
                output = verifySaml(input);
                exitCode = 0;
            } catch (Exception e) {
                output = "";
                exitCode = 1;
            }

            byte[] outBytes = output.getBytes(StandardCharsets.UTF_8);
            dout.writeInt(outBytes.length);
            dout.write(outBytes);
            dout.writeInt(exitCode);
            dout.flush();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("--persistent")) {
            persistentMode();
            return;
        }

        if (args.length < 1) {
            System.err.println("Usage: java SamlJavaXmldsig <file>");
            System.err.println("       java SamlJavaXmldsig --persistent");
            System.exit(2);
        }

        String data;
        try {
            data = new String(Files.readAllBytes(Paths.get(args[0])),
                StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
            System.exit(2);
            return;
        }

        try {
            String result = verifySaml(data);
            System.out.println(result);
            System.exit(0);
        } catch (Exception e) {
            System.err.println("REJECT: " + e.getMessage());
            System.exit(1);
        }
    }
}
