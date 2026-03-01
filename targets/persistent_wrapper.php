<?php
/**
 * Persistent wrapper for PHP fuzzing target modules.
 *
 * Keeps PHP process alive and reuses loaded modules.
 * Protocol: length-prefixed binary over stdin/stdout.
 *
 *   Request:  [4-byte BE length][input bytes]
 *   Response: [4-byte BE length][output bytes][4-byte BE exit code]
 *
 * Module must define a function `persistent_process(string $input): array`
 * returning ['output' => string, 'exit_code' => int].
 *
 * Usage: php persistent_wrapper.php ./module_path.php
 */

if ($argc < 2) {
    fwrite(STDERR, "Usage: php persistent_wrapper.php <module_path>\n");
    exit(1);
}

$modulePath = realpath($argv[1]);
if ($modulePath === false) {
    fwrite(STDERR, "Module not found: {$argv[1]}\n");
    exit(1);
}

require_once $modulePath;

if (!function_exists('persistent_process')) {
    fwrite(STDERR, "Module must define persistent_process(input) function\n");
    exit(1);
}

$stdin = fopen('php://stdin', 'rb');
$stdout = fopen('php://stdout', 'wb');

while (true) {
    // Read 4-byte BE length header
    $header = fread($stdin, 4);
    if ($header === false || strlen($header) < 4) break;

    $length = unpack('N', $header)[1];

    // Read input data
    $data = '';
    $remaining = $length;
    while ($remaining > 0) {
        $chunk = fread($stdin, $remaining);
        if ($chunk === false || $chunk === '') break 2;
        $data .= $chunk;
        $remaining -= strlen($chunk);
    }

    $output = '';
    $exitCode = 0;
    try {
        $result = persistent_process($data);
        $output = $result['output'] ?? '';
        $exitCode = $result['exit_code'] ?? 0;
    } catch (\Throwable $e) {
        $output = '';
        $exitCode = 1;
        fwrite(STDERR, "Error: {$e->getMessage()}\n");
    }

    $outBytes = $output;
    // Response: [4-byte len][output][4-byte exit code]
    $resp = pack('N', strlen($outBytes)) . $outBytes . pack('N', $exitCode);
    fwrite($stdout, $resp);
    fflush($stdout);
}

fclose($stdin);
fclose($stdout);
