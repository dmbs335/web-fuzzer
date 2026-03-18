import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

/**
 * JWT target -- Java jjwt (io.jsonwebtoken) verifier.
 *
 * jjwt is one of the most popular Java JWT libraries.
 * Supports both HMAC (HS256) and ECDSA (ES256) verification.
 *
 * Output: standardized JSON for differential comparison.
 * Exit 0 = processed, Exit 1 = parse failure.
 */
public class JwtJjwt {

    static final byte[] HS_SECRET = "secret".getBytes(StandardCharsets.UTF_8);
    // jjwt requires key >= 256 bits for HS256, so pad our secret
    static final SecretKey HMAC_KEY;

    static final String EC_PUBLIC_KEY_PEM =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX3+hdI8wUgMPJuIocOFdBxh+VZp6" +
        "GnlaqRqKGi1WSRcgg1+SLcoGu3XEP63c65tVW952Xw9lGiF5B3Q56sdssA==";

    static ECPublicKey ecPubKey;

    static {
        try {
            // Pad HS secret to 32 bytes (jjwt enforces minimum key size)
            byte[] padded = new byte[32];
            System.arraycopy(HS_SECRET, 0, padded, 0, Math.min(HS_SECRET.length, 32));
            HMAC_KEY = Keys.hmacShaKeyFor(padded);

            byte[] decoded = Base64.getDecoder().decode(EC_PUBLIC_KEY_PEM);
            KeyFactory kf = KeyFactory.getInstance("EC");
            ecPubKey = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new RuntimeException("Failed to load keys", e);
        }
    }

    public static String verifyJwt(String tokenInput) throws Exception {
        String raw = tokenInput.trim();
        String[] parts = raw.split("\\.");
        String tokenTypeObserved = parts.length == 3 ? "jws" : parts.length == 5 ? "jwe" : "unknown";

        if (parts.length < 2)
            throw new IllegalArgumentException("JWT must contain at least header and payload segments");

        // Pre-parse header
        String headerJson = new String(Base64.getUrlDecoder().decode(padBase64(parts[0])), StandardCharsets.UTF_8);
        Map<String, Object> headerMap = new Gson().fromJson(headerJson, Map.class);
        String headerAlg = String.valueOf(headerMap.getOrDefault("alg", ""));
        String typ = headerMap.containsKey("typ") ? String.valueOf(headerMap.get("typ")) : null;
        String cty = headerMap.containsKey("cty") ? String.valueOf(headerMap.get("cty")) : null;

        // Pre-parse payload
        Map<String, Object> payloadMap = new LinkedHashMap<>();
        List<String> duplicateClaimKeys = new ArrayList<>();
        List<String> duplicateHeaderKeys = findDuplicateKeys(headerJson);
        if (parts.length >= 2) {
            try {
                String payloadJson = new String(Base64.getUrlDecoder().decode(padBase64(parts[1])), StandardCharsets.UTF_8);
                payloadMap = new Gson().fromJson(payloadJson, Map.class);
                duplicateClaimKeys = findDuplicateKeys(payloadJson);
            } catch (Exception ignored) {}
        }

        boolean signatureValid = false;
        String signatureError = null;
        String effectiveAlg = headerAlg;
        String keySource = "configured";
        Boolean critProcessed = headerMap.containsKey("crit") ? false : null;
        boolean b64Mode = Boolean.FALSE.equals(headerMap.get("b64"));

        if (headerMap.containsKey("jku")) keySource = "jku";
        else if (headerMap.containsKey("jwk")) keySource = "embedded_jwk";
        else if (headerMap.containsKey("x5u")) keySource = "x5u";
        else if (headerMap.containsKey("x5c")) keySource = "x5c";

        // jjwt uses a key resolver approach - try ES256, fall back to HS256
        try {
            JwtParserBuilder parserBuilder = Jwts.parser()
                .clock(() -> new Date(1893456000L * 1000));  // fixed clock to avoid exp validation
            if (headerAlg.startsWith("ES")) {
                parserBuilder.verifyWith(ecPubKey);
            } else {
                parserBuilder.verifyWith(HMAC_KEY);
            }
            JwtParser parser = parserBuilder.build();

            Jws<Claims> jws = parser.parseSignedClaims(raw);
            signatureValid = true;
            effectiveAlg = jws.getHeader().getAlgorithm();

            Claims claims = jws.getPayload();
            payloadMap = new LinkedHashMap<>(claims);

        } catch (JwtException e) {
            signatureError = e.getClass().getSimpleName() + ": " +
                (e.getMessage() != null ? e.getMessage().substring(0, Math.min(200, e.getMessage().length())) : "");

            // If ES256 failed and alg wasn't ES*, try HS256
            if (!headerAlg.startsWith("ES") || signatureValid) {
                // already tried correct key
            } else {
                try {
                    JwtParser parser2 = Jwts.parser()
                        .verifyWith(HMAC_KEY)
                        .clock(() -> new Date(1893456000L * 1000))
                        .build();
                    Jws<Claims> jws2 = parser2.parseSignedClaims(raw);
                    signatureValid = true;
                    effectiveAlg = jws2.getHeader().getAlgorithm();
                    payloadMap = new LinkedHashMap<>(jws2.getPayload());
                    signatureError = null;
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            signatureError = e.getClass().getSimpleName() + ": " +
                (e.getMessage() != null ? e.getMessage().substring(0, Math.min(200, e.getMessage().length())) : "");
        }

        // Build result
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("signature_valid", signatureValid);
        result.put("signature_error", signatureError);
        result.put("header_alg", headerAlg);
        result.put("effective_alg", effectiveAlg);
        result.put("key_source", keySource);
        result.put("resolved_kid", headerMap.getOrDefault("kid", null));
        result.put("jwk_source", headerMap.containsKey("jwk") ? "embedded" : null);
        result.put("jku_source", headerMap.getOrDefault("jku", null));
        result.put("x5u_source", headerMap.getOrDefault("x5u", null));
        result.put("token_type_expected", "jws");
        result.put("token_type_observed", tokenTypeObserved);
        result.put("typ", typ);
        result.put("cty", cty);
        result.put("crit_processed", critProcessed);
        result.put("b64_mode", b64Mode ? "unencoded" : "normal");
        result.put("detached_payload_used", false);
        result.put("sub", payloadMap.getOrDefault("sub", null));
        result.put("iss", payloadMap.getOrDefault("iss", null));
        result.put("aud", payloadMap.getOrDefault("aud", null));
        result.put("role", payloadMap.getOrDefault("role", null));
        result.put("scope", payloadMap.getOrDefault("scope", null));
        result.put("claim_types", claimTypes(payloadMap));
        result.put("duplicate_header_keys", duplicateHeaderKeys);
        result.put("duplicate_claim_keys", duplicateClaimKeys);
        result.put("claim_parse_mode", "last_wins");
        result.put("time_valid", true);
        result.put("exp_state", payloadMap.containsKey("exp") ? "valid" : "missing");
        result.put("nbf_state", payloadMap.containsKey("nbf") ? "valid" : "missing");
        result.put("iat_state", payloadMap.containsKey("iat") ? "valid" : "missing");
        result.put("nested_jwt", "JWT".equals(cty) || payloadMap.containsKey("nested"));
        result.put("inner_alg", null);
        result.put("inner_signature_valid", null);

        return new GsonBuilder().serializeNulls().create().toJson(result);
    }

    static Map<String, String> claimTypes(Map<String, Object> payload) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String key : new String[]{"sub", "iss", "aud", "role", "scope", "exp", "nbf", "iat"}) {
            Object val = payload.get(key);
            if (val != null) {
                if (val instanceof Number) out.put(key, ((Number) val).doubleValue() % 1 == 0 ? "int" : "float");
                else if (val instanceof String) out.put(key, "str");
                else if (val instanceof List) out.put(key, "array");
                else if (val instanceof Map) out.put(key, "dict");
                else if (val instanceof Date) out.put(key, "int");
                else out.put(key, val.getClass().getSimpleName().toLowerCase());
            }
        }
        return out;
    }

    static List<String> findDuplicateKeys(String json) {
        List<String> dupes = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"([^\"]+)\"\\s*:").matcher(json);
        while (m.find()) {
            String key = m.group(1);
            if (!seen.add(key)) dupes.add(key);
        }
        Collections.sort(dupes);
        return new ArrayList<>(new LinkedHashSet<>(dupes));
    }

    static String padBase64(String s) {
        while (s.length() % 4 != 0) s += "=";
        return s;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--persistent".equals(args[0])) {
            runPersistent();
            return;
        }
        if (args.length < 1) {
            System.err.println("Usage: java JwtJjwt <input_file> | --persistent");
            System.exit(2);
        }
        try {
            String input = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
            System.out.println(verifyJwt(input));
            System.exit(0);
        } catch (Exception e) {
            System.err.println("REJECT: " + e.getMessage());
            System.exit(1);
        }
    }

    static void runPersistent() throws Exception {
        DataInputStream in = new DataInputStream(System.in);
        DataOutputStream out = new DataOutputStream(System.out);
        while (true) {
            int len;
            try { len = in.readInt(); } catch (EOFException e) { break; }
            byte[] data = new byte[len];
            in.readFully(data);
            String input = new String(data, StandardCharsets.UTF_8);
            String result;
            int exitCode;
            try {
                result = verifyJwt(input);
                exitCode = 0;
            } catch (Exception e) {
                result = "";
                exitCode = 1;
            }
            byte[] outBytes = result.getBytes(StandardCharsets.UTF_8);
            out.writeInt(outBytes.length);
            out.write(outBytes);
            out.writeInt(exitCode);
            out.flush();
        }
    }
}
