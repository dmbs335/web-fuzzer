<?php
/**
 * HTMLPurifier differential fuzzing module for persistent wrapper.
 */

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/sanitizer_diff_common.php';

$_purifier_config = HTMLPurifier_Config::createDefault();
$_purifier_config->set('Cache.DefinitionImpl', null);
$_purifier = new HTMLPurifier($_purifier_config);

function persistent_process(string $input): array {
    global $_purifier;
    try {
        $clean = $_purifier->purify($input);
        return ['output' => json_encode(build_result($clean)), 'exit_code' => 0];
    } catch (Throwable $e) {
        return ['output' => json_encode(['error' => $e->getMessage(), 'empty_output' => true]), 'exit_code' => 1];
    }
}
