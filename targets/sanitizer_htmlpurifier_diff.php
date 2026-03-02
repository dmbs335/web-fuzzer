<?php
/**
 * HTMLPurifier differential target (process mode).
 *
 * Usage: php sanitizer_htmlpurifier_diff.php <input_file>
 * Output: Standardized JSON with security signals.
 */

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/sanitizer_diff_common.php';

if ($argc < 2) {
    fwrite(STDERR, "Usage: php sanitizer_htmlpurifier_diff.php <input_file>\n");
    exit(1);
}

try {
    $html = file_get_contents($argv[1]);
    $config = HTMLPurifier_Config::createDefault();
    $config->set('Cache.DefinitionImpl', null);
    $purifier = new HTMLPurifier($config);
    $clean = $purifier->purify($html);
    echo json_encode(build_result($clean));
} catch (Throwable $e) {
    echo json_encode(['error' => $e->getMessage(), 'empty_output' => true]);
    exit(1);
}
