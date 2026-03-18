<?php
/**
 * SAML target -- php-saml / xmlseclibs (PHP).
 *
 * Verifies SAML Response signatures using OneLogin's php-saml.
 * Known vulnerabilities: xmlseclibs void canonicalization (CVE-2025-66567).
 *
 * Usage: php saml_phpsaml.php <input_file>
 */

$FIXTURES_DIR = __DIR__ . '/saml_fixtures';

$SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
$DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

function getText($elem) {
    if ($elem === null) return null;
    $text = $elem->textContent;
    return $text ?: null;
}

function firstReferenceUri($xpath) {
    $refs = $xpath->query('//ds:Reference');
    if ($refs->length === 0) return null;
    $uri = $refs->item(0)->getAttribute('URI') ?: '';
    return $uri !== '' ? $uri : null;
}

function nameIdObservability($xpath, $assertion) {
    if ($assertion === null) return [0, 'missing'];
    $nameIds = $xpath->query('.//saml:NameID', $assertion);
    if ($nameIds->length === 0) return [0, 'missing'];
    return [$nameIds->length, getText($nameIds->item(0)) === null ? 'empty' : 'nonempty'];
}

function verifySaml($xmlInput) {
    global $FIXTURES_DIR, $SAML_NS, $DS_NS;

    if (trim($xmlInput) === '' || strpos($xmlInput, '<') === false) {
        throw new \InvalidArgumentException('Not XML');
    }

    $signatureValid = false;
    $signatureError = null;

    // Load IdP cert
    $certPem = file_get_contents("$FIXTURES_DIR/idp_cert.pem");
    $certClean = str_replace(
        ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r"],
        '', $certPem
    );

    // Try php-saml
    try {
        if (class_exists('OneLogin\\Saml2\\Response')) {
            $settingsInfo = [
                'strict' => false,
                'sp' => [
                    'entityId' => 'https://sp.example.com',
                    'assertionConsumerService' => [
                        'url' => 'https://sp.example.com/acs',
                        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                    ],
                ],
                'idp' => [
                    'entityId' => 'https://idp.example.com',
                    'singleSignOnService' => [
                        'url' => 'https://idp.example.com/sso',
                    ],
                    'x509cert' => $certClean,
                ],
            ];

            $settings = new \OneLogin\Saml2\Settings($settingsInfo);
            $b64 = base64_encode($xmlInput);
            $response = new \OneLogin\Saml2\Response($settings, $b64);

            try {
                $signatureValid = $response->isValid();
            } catch (\Exception $e) {
                $signatureError = substr($e->getMessage(), 0, 500);
            }

            if (!$signatureValid && !$signatureError) {
                $signatureError = $response->getError() ?: 'Validation failed';
            }
        } else {
            $signatureError = 'php-saml not installed';
        }
    } catch (\Exception $e) {
        $signatureError = substr($e->getMessage(), 0, 500);
    }

    // Parse XML for field extraction
    $doc = new DOMDocument();
    $doc->loadXML($xmlInput, LIBXML_NONET | LIBXML_NOENT);
    $xpath = new DOMXPath($doc);
    $xpath->registerNamespace('saml', $SAML_NS);
    $xpath->registerNamespace('ds', $DS_NS);

    // Assertions
    $assertions = $xpath->query('//saml:Assertion');

    // Find signed assertion by matching Reference URI to Assertion ID
    $signedAssertion = null;
    $selectedAssertionIndex = null;
    $selectionMode = 'no_assertion';
    $referenceUri = null;
    $refs = $xpath->query('//ds:Reference');
    foreach ($refs as $ref) {
        $uri = $ref->getAttribute('URI') ?: '';
        if ($referenceUri === null && $uri !== '') $referenceUri = $uri;
        if (str_starts_with($uri, '#')) {
            $targetId = substr($uri, 1);
            foreach ($assertions as $idx => $a) {
                if ($a->getAttribute('ID') === $targetId) {
                    $signedAssertion = $a;
                    $selectedAssertionIndex = $idx;
                    $selectionMode = 'reference_uri';
                    break 2;
                }
            }
        }
    }
    if ($signedAssertion === null && $assertions->length > 0) {
        $signedAssertion = $assertions->item(0);
        $selectedAssertionIndex = 0;
        $selectionMode = 'first_assertion_fallback';
    }
    if ($referenceUri === null) $referenceUri = firstReferenceUri($xpath);

    $subject = null;
    $subjectFormat = null;
    $issuer = null;
    $issuerSource = 'none';
    $audience = null;
    $audienceCount = 0;
    $attributes = [];
    $assertionId = null;
    $nameIdCount = 0;
    $emptyNameIdSemantics = 'missing';

    if ($signedAssertion !== null) {
        $assertionId = $signedAssertion->getAttribute('ID') ?: null;
        // Extract from signed assertion only
        $nameIds = $xpath->query('.//saml:NameID', $signedAssertion);
        $subject = $nameIds->length > 0 ? getText($nameIds->item(0)) : null;
        $subjectFormat = $nameIds->length > 0 ? $nameIds->item(0)->getAttribute('Format') : null;
        [$nameIdCount, $emptyNameIdSemantics] = nameIdObservability($xpath, $signedAssertion);

        $issuers = $xpath->query('saml:Issuer', $signedAssertion);
        $issuer = $issuers->length > 0 ? getText($issuers->item(0)) : null;
        if ($issuer !== null) $issuerSource = 'assertion';

        $audiences = $xpath->query('.//saml:Audience', $signedAssertion);
        $audienceCount = $audiences->length;
        $audience = $audiences->length > 0 ? getText($audiences->item(0)) : null;

        $attrElems = $xpath->query('.//saml:Attribute', $signedAssertion);
        foreach ($attrElems as $attr) {
            $name = $attr->getAttribute('Name');
            $vals = [];
            $valueElems = $xpath->query('saml:AttributeValue', $attr);
            foreach ($valueElems as $v) {
                $text = trim($v->textContent);
                if ($text) $vals[] = $text;
            }
            if ($name && !empty($vals)) {
                $attributes[$name] = count($vals) === 1 ? $vals[0] : $vals;
            }
        }
    }

    // Response-level issuer as fallback
    if ($issuer === null) {
        $respIssuers = $xpath->query('//saml:Issuer');
        $issuer = $respIssuers->length > 0 ? getText($respIssuers->item(0)) : null;
        if ($issuer !== null) $issuerSource = 'response';
    }

    $referenceTargetId = ($referenceUri !== null && str_starts_with($referenceUri, '#'))
        ? substr($referenceUri, 1)
        : null;
    $referenceMatchesSelectedAssertion = ($referenceTargetId !== null && $assertionId !== null)
        ? ($referenceTargetId === $assertionId)
        : null;

    // Algorithms
    $algorithms = [];
    $sigMethods = $xpath->query('//ds:SignatureMethod');
    if ($sigMethods->length > 0) {
        $algo = $sigMethods->item(0)->getAttribute('Algorithm') ?: '';
        $al = strtolower($algo);
        if (strpos($al, 'hmac') !== false) $algorithms['signature'] = explode('#', $algo)[count(explode('#', $algo))-1] ?? $algo;
        elseif (strpos($al, 'sha256') !== false) $algorithms['signature'] = 'rsa-sha256';
        elseif (strpos($al, 'sha384') !== false) $algorithms['signature'] = 'rsa-sha384';
        elseif (strpos($al, 'sha512') !== false) $algorithms['signature'] = 'rsa-sha512';
        elseif (strpos($al, 'sha1') !== false) $algorithms['signature'] = 'rsa-sha1';
        else $algorithms['signature'] = $algo;
    }
    $digMethods = $xpath->query('//ds:DigestMethod');
    if ($digMethods->length > 0) {
        $algo = $digMethods->item(0)->getAttribute('Algorithm') ?: '';
        $al = strtolower($algo);
        if (strpos($al, 'sha256') !== false) $algorithms['digest'] = 'sha256';
        elseif (strpos($al, 'sha384') !== false) $algorithms['digest'] = 'sha384';
        elseif (strpos($al, 'sha512') !== false) $algorithms['digest'] = 'sha512';
        elseif (strpos($al, 'sha1') !== false) $algorithms['digest'] = 'sha1';
        elseif (strpos($al, 'md5') !== false) $algorithms['digest'] = 'md5';
        else $algorithms['digest'] = $algo;
    }

    return json_encode([
        'signature_valid' => $signatureValid,
        'signature_error' => $signatureError,
        'subject' => $subject,
        'subject_format' => $subjectFormat ?: null,
        'issuer' => $issuer,
        'audience' => $audience,
        'attributes' => (object)$attributes,
        'assertion_count' => $assertions->length,
        'assertion_id' => $assertionId,
        'selected_assertion_index' => $selectedAssertionIndex,
        'selection_mode' => $selectionMode,
        'reference_uri' => $referenceUri,
        'reference_matches_selected_assertion' => $referenceMatchesSelectedAssertion,
        'signature_count' => $xpath->query('//ds:Signature')->length,
        'issuer_source' => $issuerSource,
        'audience_count' => $audienceCount,
        'nameid_count' => $nameIdCount,
        'empty_nameid_semantics' => $emptyNameIdSemantics,
        'algorithms' => (object)$algorithms,
        'validated_signature_algorithm' => $signatureValid && $sigMethods->length > 0
            ? ($sigMethods->item(0)->getAttribute('Algorithm') ?: null)
            : null,
    ], JSON_UNESCAPED_SLASHES);
}

// -- Main (skip when loaded as module) --
if (realpath(__FILE__) === realpath($argv[0] ?? '')) {
    if ($argc < 2) {
        fwrite(STDERR, "Usage: php saml_phpsaml.php <input_file>\n");
        exit(2);
    }

    try {
        $autoloadPath = __DIR__ . '/vendor/autoload.php';
        if (file_exists($autoloadPath)) {
            require_once $autoloadPath;
        }

        $xml = file_get_contents($argv[1]);
        echo verifySaml($xml) . "\n";
        exit(0);
    } catch (\Exception $e) {
        fwrite(STDERR, "REJECT: " . $e->getMessage() . "\n");
        exit(1);
    }
}
