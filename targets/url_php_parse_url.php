<?php
/**
 * URL parser target — PHP parse_url().
 *
 * Parses URLs using PHP's parse_url() and outputs parsed
 * components as JSON for differential comparison.
 *
 * parse_url() is one of the most SSRF-relevant parsers:
 *   - Does NOT validate schemes or hostnames
 *   - Backslash handling differs from browsers
 *   - Userinfo parsing can be exploited for host confusion
 *   - No percent-decoding normalization
 *   - Tab/newline stripping differs from other parsers
 *
 * References:
 *   - PHP docs: parse_url()
 *   - Orange Tsai, "A New Era of SSRF" (BlackHat 2017)
 *   - CVE-2024-4577 (PHP CGI argument injection)
 */

if ($argc < 2) {
    fwrite(STDERR, "Usage: php url_php_parse_url.php <file>\n");
    exit(2);
}

$data = @file_get_contents($argv[1]);
if ($data === false) {
    fwrite(STDERR, "IO error: cannot read file\n");
    exit(2);
}

$data = trim($data);
if ($data === '') {
    fwrite(STDERR, "REJECT: Empty input\n");
    exit(1);
}

$parsed = parse_url($data);
if ($parsed === false) {
    fwrite(STDERR, "REJECT: parse_url() returned false\n");
    exit(1);
}

// Extract userinfo
$userinfo = '';
if (isset($parsed['user'])) {
    $userinfo = $parsed['user'];
    if (isset($parsed['pass'])) {
        $userinfo .= ':' . $parsed['pass'];
    }
}

$result = array(
    'scheme'   => isset($parsed['scheme']) ? $parsed['scheme'] : '',
    'userinfo' => $userinfo,
    'host'     => isset($parsed['host']) ? $parsed['host'] : '',
    'port'     => isset($parsed['port']) ? (string)$parsed['port'] : '',
    'path'     => isset($parsed['path']) ? $parsed['path'] : '',
    'query'    => isset($parsed['query']) ? $parsed['query'] : '',
    'fragment' => isset($parsed['fragment']) ? $parsed['fragment'] : '',
);

echo json_encode($result, JSON_UNESCAPED_SLASHES) . "\n";
exit(0);
