<?php
/**
 * PHP built-in parse echo backend for WAF bypass finding validation.
 *
 * Uses PHP's native $_POST / $_FILES / json_decode() so we can observe
 * what PHP applications see after WAF bypass.
 *
 * Port: 19113
 * Usage: php -S 0.0.0.0:8084 php_parse_backend.php
 */

header('Content-Type: application/json');
header('X-Backend-Reached: true');

// ── helpers ──────────────────────────────────────────────────────────────────

function flatten_json($obj, $prefix = '', $depth = 6): array {
    if ($depth <= 0) return [];
    $result = [];
    if (is_array($obj)) {
        foreach ($obj as $k => $v) {
            $key = $prefix !== '' ? "{$prefix}.{$k}" : (string)$k;
            $result = array_merge($result, flatten_json($v, $key, $depth - 1));
        }
    } else {
        $key = $prefix !== '' ? $prefix : '_root';
        $result[$key] = [$obj !== null ? (string)$obj : ''];
    }
    return $result;
}

function safe_header(string $name, string $value): void {
    // Strip CR/LF from header values to prevent injection
    $value = preg_replace('/[\r\n]/', ' ', $value);
    header("{$name}: {$value}");
}

// ── health check ──────────────────────────────────────────────────────────────

$path = $_SERVER['REQUEST_URI'] ?? '/';
$path = strtok($path, '?');

if ($path === '/health') {
    echo json_encode(['status' => 'ok']);
    exit;
}

// ── parse ─────────────────────────────────────────────────────────────────────

$raw = file_get_contents('php://input');
$ct  = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
$ct_lower = strtolower(explode(';', $ct)[0]);

$fields       = [];
$parse_status = 'ok';
$parse_format = 'unknown';
$parse_error  = '';

if (strpos($ct_lower, 'multipart/form-data') !== false) {
    // PHP auto-populates $_POST (text fields) and $_FILES (file fields)
    $parse_format = 'multipart';
    foreach ($_POST as $k => $v) {
        $fields[$k] = is_array($v) ? $v : [$v];
    }
    foreach ($_FILES as $k => $f) {
        if (isset($f['tmp_name']) && is_file($f['tmp_name'])) {
            $content = file_get_contents($f['tmp_name']);
            $fields[$k] = [substr($content, 0, 500)];
        } elseif (is_array($f['tmp_name'] ?? null)) {
            // Multiple files with same name
            foreach ($f['tmp_name'] as $i => $tmp) {
                if (is_file($tmp)) {
                    $fields[$k][] = substr(file_get_contents($tmp), 0, 500);
                }
            }
        }
    }
    if (empty($fields)) {
        $parse_status = 'skip';
    }

} elseif ($ct_lower === 'application/x-www-form-urlencoded') {
    $parse_format = 'form';
    // PHP auto-populates $_POST for urlencoded
    foreach ($_POST as $k => $v) {
        $fields[$k] = is_array($v) ? $v : [$v];
    }
    // Fallback: manual parse_str on raw input (handles evasion variants
    // where PHP doesn't auto-populate $_POST e.g. PUT requests)
    if (empty($fields) && $raw !== '') {
        $manual = [];
        parse_str($raw, $manual);
        foreach ($manual as $k => $v) {
            $fields[$k] = is_array($v) ? $v : [$v];
        }
    }
    if (empty($fields)) {
        $parse_status = 'skip';
    }

} elseif (strpos($ct_lower, 'json') !== false) {
    $parse_format = 'json';
    if ($raw !== '') {
        $decoded = json_decode($raw, true);
        if ($decoded !== null) {
            $fields = flatten_json($decoded);
        } else {
            $parse_status = 'error';
            $parse_error  = 'json_decode failed: ' . json_last_error_msg();
        }
    } else {
        $parse_status = 'skip';
    }

} else {
    // Unknown content type — try form parse on raw body as best-effort
    if ($raw !== '') {
        $manual = [];
        parse_str($raw, $manual);
        if (!empty($manual)) {
            $fields = [];
            foreach ($manual as $k => $v) {
                $fields[$k] = is_array($v) ? $v : [$v];
            }
            $parse_format = 'form_raw';
        } else {
            $parse_status = 'skip';
        }
    } else {
        $parse_status = 'skip';
    }
}

// ── emit headers ──────────────────────────────────────────────────────────────

$field_count = count($fields);
$field_names = array_slice(array_keys($fields), 0, 20);

safe_header('X-Parse-Status',       $parse_status);
safe_header('X-Parse-Format',       $parse_format);
safe_header('X-Parsed-Field-Count', (string)$field_count);
safe_header('X-Parsed-Field-Names', implode(',', $field_names));
if ($parse_error !== '') {
    safe_header('X-Parse-Error', substr($parse_error, 0, 200));
}

// Per-field value headers (first value, truncated, ASCII-safe)
foreach (array_slice($field_names, 0, 10) as $name) {
    $vs = $fields[$name] ?? [];
    if (!empty($vs)) {
        $safe_name = preg_replace('/[^A-Za-z0-9_-]/', '-', substr($name, 0, 30));
        $safe_val  = substr(preg_replace('/[\x00-\x1f\x7f-\xff]/', '?', (string)$vs[0]), 0, 100);
        safe_header("X-Parsed-{$safe_name}", $safe_val);
    }
}

// ── emit body ────────────────────────────────────────────────────────────────

// Truncate field values for body
$safe_fields = [];
foreach ($fields as $k => $vs) {
    $safe_fields[$k] = array_map(fn($v) => substr((string)$v, 0, 500), (array)$vs);
}

$response = [
    'status'      => $parse_status,
    'format'      => $parse_format,
    'fields'      => $safe_fields,
    'field_count' => $field_count,
    'raw_size'    => strlen($raw),
];
if ($parse_error !== '') {
    $response['error'] = $parse_error;
}

echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
