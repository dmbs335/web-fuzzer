package waf.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class ParseEchoController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    @RequestMapping(value = "/**",
                    method = {RequestMethod.POST, RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE, RequestMethod.GET})
    public ResponseEntity<Map<String, Object>> echo(HttpServletRequest req) {
        String ct = Optional.ofNullable(req.getContentType()).orElse("").toLowerCase();
        Map<String, List<String>> fields = new LinkedHashMap<>();
        String parseStatus = "ok";
        String parseFormat = "unknown";
        String parseError  = "";

        try {
            if (ct.startsWith("multipart/form-data")) {
                parseFormat = "multipart";
                if (req instanceof MultipartHttpServletRequest mreq) {
                    mreq.getParameterMap().forEach((k, vs) -> fields.put(k, Arrays.asList(vs)));
                    Map<String, MultipartFile> fileMap = mreq.getFileMap();
                    for (Map.Entry<String, MultipartFile> e : fileMap.entrySet()) {
                        byte[] bytes = e.getValue().getBytes();
                        String val = new String(bytes, StandardCharsets.ISO_8859_1);
                        if (val.length() > 500) val = val.substring(0, 500);
                        fields.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).add(val);
                    }
                } else {
                    parseStatus = "error";
                    parseError  = "request is not MultipartHttpServletRequest";
                }
                if (fields.isEmpty()) parseStatus = "skip";

            } else if (ct.startsWith("application/x-www-form-urlencoded")) {
                parseFormat = "form";
                req.getParameterMap().forEach((k, vs) -> fields.put(k, Arrays.asList(vs)));
                if (fields.isEmpty()) parseStatus = "skip";

            } else if (ct.contains("json")) {
                parseFormat = "json";
                byte[] rawBytes = req.getInputStream().readAllBytes();
                if (rawBytes.length > 0) {
                    JsonNode node = MAPPER.readTree(rawBytes);
                    flattenJson(node, "", fields, 6);
                } else {
                    parseStatus = "skip";
                }

            } else {
                // Unknown — try parameter map (works for some edge cases)
                Map<String, String[]> params = req.getParameterMap();
                if (!params.isEmpty()) {
                    params.forEach((k, vs) -> fields.put(k, Arrays.asList(vs)));
                    parseFormat = "form_raw";
                } else {
                    parseStatus = "skip";
                }
            }
        } catch (Exception e) {
            parseStatus = "error";
            parseError  = e.getMessage() != null ? e.getMessage().substring(0, Math.min(200, e.getMessage().length())) : e.getClass().getSimpleName();
        }

        // Truncate values
        Map<String, List<String>> safeFields = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : fields.entrySet()) {
            safeFields.put(e.getKey(),
                e.getValue().stream()
                    .map(v -> v.length() > 500 ? v.substring(0, 500) : v)
                    .collect(Collectors.toList()));
        }

        int fieldCount = safeFields.size();
        List<String> fieldNames = new ArrayList<>(safeFields.keySet());
        if (fieldNames.size() > 20) fieldNames = fieldNames.subList(0, 20);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status",      parseStatus);
        body.put("format",      parseFormat);
        body.put("fields",      safeFields);
        body.put("field_count", fieldCount);
        if (!parseError.isEmpty()) body.put("error", parseError);

        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.add("X-Backend-Reached",    "true");
        headers.add("X-Parse-Status",       parseStatus);
        headers.add("X-Parse-Format",       parseFormat);
        headers.add("X-Parsed-Field-Count", String.valueOf(fieldCount));
        headers.add("X-Parsed-Field-Names", String.join(",", fieldNames));
        if (!parseError.isEmpty()) headers.add("X-Parse-Error", parseError);

        // Per-field headers
        for (String name : fieldNames.subList(0, Math.min(10, fieldNames.size()))) {
            List<String> vs = safeFields.get(name);
            if (vs != null && !vs.isEmpty()) {
                String safeName = name.length() > 30 ? name.substring(0, 30) : name;
                safeName = safeName.replaceAll("[^\\x20-\\x7e]", "?");
                String safeVal = vs.get(0).length() > 100 ? vs.get(0).substring(0, 100) : vs.get(0);
                safeVal = safeVal.replaceAll("[\r\n]", " ");
                headers.add("X-Parsed-" + safeName, safeVal);
            }
        }

        return ResponseEntity.ok().headers(headers).body(body);
    }

    private void flattenJson(JsonNode node, String prefix, Map<String, List<String>> out, int depth) {
        if (depth <= 0) return;
        if (node.isObject()) {
            node.fields().forEachRemaining(e -> {
                String key = prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey();
                flattenJson(e.getValue(), key, out, depth - 1);
            });
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                String key = prefix.isEmpty() ? "[" + i + "]" : prefix + "[" + i + "]";
                flattenJson(node.get(i), key, out, depth - 1);
            }
        } else {
            String key = prefix.isEmpty() ? "_root" : prefix;
            out.computeIfAbsent(key, k -> new ArrayList<>()).add(node.asText(""));
        }
    }
}
