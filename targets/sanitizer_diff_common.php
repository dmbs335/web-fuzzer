<?php
/**
 * Shared analysis utilities for sanitizer differential fuzzing targets.
 *
 * Extracts security-relevant signals from sanitized HTML output
 * and produces a standardized JSON schema for cross-library comparison.
 *
 * PHP port of sanitizer_diff_common.js — uses DOMDocument.
 */

define('URI_ATTRS', ['href', 'src', 'action', 'formaction', 'poster', 'data', 'codebase']);

function analyze_sanitized(string $html): array {
    $empty = [
        'elements' => [], 'attributes' => [],
        'has_script' => false, 'has_event_handler' => false,
        'has_javascript_uri' => false, 'has_data_uri' => false,
        'has_svg' => false, 'has_math' => false,
        'has_style' => false, 'has_form' => false,
        'has_base' => false, 'has_iframe' => false,
        'has_object_embed' => false, 'has_noscript' => false,
    ];

    if (empty(trim($html))) {
        return $empty;
    }

    $elements = [];
    $attributes = [];
    $has_script = false;
    $has_event_handler = false;
    $has_javascript_uri = false;
    $has_data_uri = false;

    libxml_use_internal_errors(true);
    $doc = new DOMDocument();
    $doc->loadHTML('<body>' . $html . '</body>', LIBXML_NOERROR | LIBXML_NOWARNING);
    libxml_clear_errors();

    $walk = function($node) use (&$walk, &$elements, &$attributes,
                                   &$has_script, &$has_event_handler,
                                   &$has_javascript_uri, &$has_data_uri) {
        if ($node->nodeType !== XML_ELEMENT_NODE) return;

        $tag = strtolower($node->nodeName);
        // Skip wrapper elements added by DOMDocument
        if ($tag === 'html' || $tag === 'body' || $tag === 'head') {
            foreach ($node->childNodes as $child) $walk($child);
            return;
        }

        $elements[$tag] = true;
        if ($tag === 'script') $has_script = true;

        if ($node->hasAttributes()) {
            foreach ($node->attributes as $attr) {
                $name = strtolower($attr->nodeName);
                $attributes[$name] = true;

                if (preg_match('/^on[a-z]/i', $name)) {
                    $has_event_handler = true;
                }
                if (in_array($name, URI_ATTRS) && $attr->nodeValue) {
                    if (preg_match('/^\s*javascript\s*:/i', $attr->nodeValue)) {
                        $has_javascript_uri = true;
                    }
                    if (preg_match('/^\s*data\s*:\s*text\/html/i', $attr->nodeValue)) {
                        $has_data_uri = true;
                    }
                }
            }
        }

        foreach ($node->childNodes as $child) $walk($child);
    };

    $body = $doc->getElementsByTagName('body')->item(0);
    if ($body) {
        foreach ($body->childNodes as $child) $walk($child);
    }

    $elemKeys = array_keys($elements);
    sort($elemKeys);
    $attrKeys = array_keys($attributes);
    sort($attrKeys);

    return [
        'elements' => $elemKeys,
        'attributes' => $attrKeys,
        'has_script' => $has_script,
        'has_event_handler' => $has_event_handler,
        'has_javascript_uri' => $has_javascript_uri,
        'has_data_uri' => $has_data_uri,
        'has_svg' => isset($elements['svg']),
        'has_math' => isset($elements['math']),
        'has_style' => isset($elements['style']),
        'has_form' => isset($elements['form']),
        'has_base' => isset($elements['base']),
        'has_iframe' => isset($elements['iframe']),
        'has_object_embed' => isset($elements['object']) || isset($elements['embed']) || isset($elements['applet']),
        'has_noscript' => isset($elements['noscript']),
    ];
}

function build_result(string $sanitized): array {
    $analysis = analyze_sanitized($sanitized);
    return [
        'sanitized' => mb_substr($sanitized, 0, 2000),
        'elements_kept' => $analysis['elements'],
        'attributes_kept' => $analysis['attributes'],
        'has_script' => $analysis['has_script'],
        'has_event_handler' => $analysis['has_event_handler'],
        'has_javascript_uri' => $analysis['has_javascript_uri'],
        'has_data_uri' => $analysis['has_data_uri'],
        'has_svg' => $analysis['has_svg'],
        'has_math' => $analysis['has_math'],
        'has_style' => $analysis['has_style'],
        'has_form' => $analysis['has_form'],
        'has_base' => $analysis['has_base'],
        'has_iframe' => $analysis['has_iframe'],
        'has_object_embed' => $analysis['has_object_embed'],
        'has_noscript' => $analysis['has_noscript'],
        'empty_output' => empty(trim($sanitized)),
        'error' => null,
    ];
}
