# Shared analysis utilities for sanitizer differential fuzzing targets.
#
# Extracts security-relevant signals from sanitized HTML output
# and produces a standardized JSON schema for cross-library comparison.
#
# Ruby port of sanitizer_diff_common.js — uses Nokogiri.

require 'nokogiri'
require 'json'

EVENT_HANDLER_RE = /\Aon[a-z]/i
JS_URI_RE = /\A\s*javascript\s*:/i
DATA_HTML_RE = /\A\s*data\s*:\s*text\/html/i

URI_ATTRS = Set.new(%w[href src action formaction poster data codebase])

def analyze_sanitized(html)
  empty = {
    'elements' => [], 'attributes' => [],
    'has_script' => false, 'has_event_handler' => false,
    'has_javascript_uri' => false, 'has_data_uri' => false,
    'has_svg' => false, 'has_math' => false,
    'has_style' => false, 'has_form' => false,
    'has_base' => false, 'has_iframe' => false,
    'has_object_embed' => false, 'has_noscript' => false,
  }

  return empty if html.nil? || html.strip.empty?

  doc = Nokogiri::HTML.fragment(html)
  elements = Set.new
  attributes = Set.new
  has_script = false
  has_event_handler = false
  has_javascript_uri = false
  has_data_uri = false

  doc.traverse do |node|
    next unless node.element?

    tag = node.name.downcase
    elements.add(tag)
    has_script = true if tag == 'script'

    node.attributes.each do |name, attr|
      name = name.downcase
      attributes.add(name)
      has_event_handler = true if name.match?(EVENT_HANDLER_RE)
      if URI_ATTRS.include?(name) && attr.value
        has_javascript_uri = true if attr.value.match?(JS_URI_RE)
        has_data_uri = true if attr.value.match?(DATA_HTML_RE)
      end
    end
  end

  {
    'elements' => elements.to_a.sort,
    'attributes' => attributes.to_a.sort,
    'has_script' => has_script,
    'has_event_handler' => has_event_handler,
    'has_javascript_uri' => has_javascript_uri,
    'has_data_uri' => has_data_uri,
    'has_svg' => elements.include?('svg'),
    'has_math' => elements.include?('math'),
    'has_style' => elements.include?('style'),
    'has_form' => elements.include?('form'),
    'has_base' => elements.include?('base'),
    'has_iframe' => elements.include?('iframe'),
    'has_object_embed' => !(elements & Set['object', 'embed', 'applet']).empty?,
    'has_noscript' => elements.include?('noscript'),
  }
end

def build_result(sanitized)
  analysis = analyze_sanitized(sanitized)
  {
    'sanitized' => sanitized[0, 2000],
    'elements_kept' => analysis['elements'],
    'attributes_kept' => analysis['attributes'],
    'has_script' => analysis['has_script'],
    'has_event_handler' => analysis['has_event_handler'],
    'has_javascript_uri' => analysis['has_javascript_uri'],
    'has_data_uri' => analysis['has_data_uri'],
    'has_svg' => analysis['has_svg'],
    'has_math' => analysis['has_math'],
    'has_style' => analysis['has_style'],
    'has_form' => analysis['has_form'],
    'has_base' => analysis['has_base'],
    'has_iframe' => analysis['has_iframe'],
    'has_object_embed' => analysis['has_object_embed'],
    'has_noscript' => analysis['has_noscript'],
    'empty_output' => sanitized.nil? || sanitized.strip.empty?,
    'error' => nil,
  }
end
