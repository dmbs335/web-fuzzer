<?php
/**
 * Persistent module -- php-saml SAML verifier.
 *
 * Exports persistent_process(input) for use with persistent_wrapper.php.
 */

// Load composer autoload
$autoloadPath = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

// Load the main target (defines verifySaml function)
require_once __DIR__ . '/saml_phpsaml.php';

function persistent_process(string $input): array {
    // Guard: empty or clearly non-XML input
    if (trim($input) === '' || strpos($input, '<') === false) {
        return ['output' => '', 'exit_code' => 1];
    }

    // Suppress libxml warnings/errors that could cause output corruption
    $prevUseErrors = libxml_use_internal_errors(true);
    try {
        $output = verifySaml($input);
        libxml_clear_errors();
        libxml_use_internal_errors($prevUseErrors);
        return ['output' => $output, 'exit_code' => 0];
    } catch (\Throwable $e) {
        libxml_clear_errors();
        libxml_use_internal_errors($prevUseErrors);
        return ['output' => '', 'exit_code' => 1];
    }
}
