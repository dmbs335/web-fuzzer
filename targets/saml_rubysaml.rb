#!/usr/bin/env ruby
# SAML target -- ruby-saml (Nokogiri + REXML dual-parser).
#
# Verifies SAML Response signatures using ruby-saml.
# Known vulnerabilities: CVE-2025-25291/25292 (parser differential),
# CVE-2025-66567/66568 (void canonicalization).
#
# Usage: ruby saml_rubysaml.rb <input_file>

require 'json'
require 'base64'
require 'rexml/document'

FIXTURES_DIR = File.join(File.dirname(__FILE__), 'saml_fixtures')

SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion'
DS_NS = 'http://www.w3.org/2000/09/xmldsig#'

# Match ruby-saml's Utils.element_text behavior: element.texts.map(&:value).join
# REXML .text only returns the first Text child (truncates at comment/PI).
# .texts returns ALL Text children, skipping comments and PIs.
def element_text(elem)
  return nil if elem.nil?
  t = elem.texts.map(&:value).join.strip
  t.empty? ? nil : t
end

def first_reference_uri(doc)
  ref = REXML::XPath.first(doc, '//ds:Reference', 'ds' => DS_NS)
  ref&.attributes&.[]('URI')
end

def signature_count(doc)
  REXML::XPath.match(doc, '//ds:Signature', 'ds' => DS_NS).length
end

def nameid_observability(assertion)
  return [0, 'missing'] unless assertion
  name_ids = REXML::XPath.match(assertion, './/saml:NameID', 'saml' => SAML_NS)
  return [0, 'missing'] if name_ids.empty?
  [name_ids.length, element_text(name_ids[0]).nil? ? 'empty' : 'nonempty']
end

def verify_saml(xml_input)
  raise ArgumentError, 'empty input' if xml_input.nil? || xml_input.strip.empty?
  raise ArgumentError, 'not XML' unless xml_input.include?('<')

  signature_valid = false
  signature_error = nil

  begin
    require 'ruby-saml'

    idp_cert = File.read(File.join(FIXTURES_DIR, 'idp_cert.pem'))

    settings = OneLogin::RubySaml::Settings.new
    settings.idp_cert = idp_cert
    settings.idp_entity_id = 'https://idp.example.com'
    settings.sp_entity_id = 'https://sp.example.com'
    settings.assertion_consumer_service_url = 'https://sp.example.com/acs'
    settings.soft = true

    b64_response = Base64.encode64(xml_input)
    response = OneLogin::RubySaml::Response.new(b64_response, settings: settings)

    begin
      signature_valid = response.is_valid?
    rescue => e
      signature_error = e.message[0..500]
    end

    unless signature_valid
      signature_error ||= response.errors.join('; ') rescue 'Validation failed'
    end
  rescue LoadError
    signature_error = 'ruby-saml not installed'
  rescue => e
    signature_error = e.message[0..500]
  end

  # Extract fields from the signed assertion (not full document)
  doc = REXML::Document.new(xml_input)

  assertions = REXML::XPath.match(doc, '//saml:Assertion', 'saml' => SAML_NS)

  # Find signed assertion by matching Reference URI to Assertion ID
  signed_assertion = nil
  selected_assertion_index = nil
  selection_mode = 'no_assertion'
  reference_uri = nil
  REXML::XPath.each(doc, '//ds:Reference', 'ds' => DS_NS) do |ref|
    uri = ref.attributes['URI'] || ''
    reference_uri ||= uri unless uri.empty?
    if uri.start_with?('#')
      target_id = uri[1..]
      assertions.each_with_index do |a, idx|
        if a.attributes['ID'] == target_id
          signed_assertion = a
          selected_assertion_index = idx
          selection_mode = 'reference_uri'
          break
        end
      end
      break if signed_assertion
    end
  end
  if signed_assertion.nil? && assertions[0]
    signed_assertion = assertions[0]
    selected_assertion_index = 0
    selection_mode = 'first_assertion_fallback'
  end
  reference_uri ||= first_reference_uri(doc)

  subject = nil
  subject_format = nil
  issuer = nil
  issuer_source = 'none'
  audience = nil
  audience_count = 0
  attributes = {}
  assertion_id = nil
  nameid_count = 0
  empty_nameid_semantics = 'missing'

  if signed_assertion
    assertion_id = signed_assertion.attributes['ID']
    name_ids = REXML::XPath.match(signed_assertion, './/saml:NameID', 'saml' => SAML_NS)
    unless name_ids.empty?
      subject = element_text(name_ids[0])
      subject_format = name_ids[0].attributes['Format']
    end
    nameid_count, empty_nameid_semantics = nameid_observability(signed_assertion)

    issuers = REXML::XPath.match(signed_assertion, 'saml:Issuer', 'saml' => SAML_NS)
    issuer = element_text(issuers[0]) unless issuers.empty?
    issuer_source = 'assertion' if issuer

    audiences = REXML::XPath.match(signed_assertion, './/saml:Audience', 'saml' => SAML_NS)
    audience_count = audiences.length
    audience = element_text(audiences[0]) unless audiences.empty?

    REXML::XPath.each(signed_assertion, './/saml:Attribute', 'saml' => SAML_NS) do |attr|
      name = attr.attributes['Name']
      vals = REXML::XPath.match(attr, 'saml:AttributeValue', 'saml' => SAML_NS)
        .map { |v| element_text(v) }
        .compact
      attributes[name] = vals.length == 1 ? vals[0] : vals if name && !vals.empty?
    end
  end

  # Response-level issuer as fallback
  unless issuer
    resp_issuers = REXML::XPath.match(doc, '//saml:Issuer', 'saml' => SAML_NS)
    issuer = element_text(resp_issuers[0]) unless resp_issuers.empty?
    issuer_source = 'response' if issuer
  end

  reference_target_id = reference_uri&.start_with?('#') ? reference_uri[1..] : nil
  reference_matches_selected_assertion =
    if reference_target_id && assertion_id
      reference_target_id == assertion_id
    else
      nil
    end

  # Algorithms
  algorithms = {}
  sig_method = REXML::XPath.first(doc, '//ds:SignatureMethod', 'ds' => DS_NS)
  if sig_method
    algo = sig_method.attributes['Algorithm'] || ''
    al = algo.downcase
    algorithms['signature'] = if al.include?('hmac') then algo.split('#').last
                              elsif al.include?('sha256') then 'rsa-sha256'
                              elsif al.include?('sha384') then 'rsa-sha384'
                              elsif al.include?('sha512') then 'rsa-sha512'
                              elsif al.include?('sha1') then 'rsa-sha1'
                              else algo end
  end
  digest_method = REXML::XPath.first(doc, '//ds:DigestMethod', 'ds' => DS_NS)
  if digest_method
    algo = digest_method.attributes['Algorithm'] || ''
    al = algo.downcase
    algorithms['digest'] = if al.include?('sha256') then 'sha256'
                           elsif al.include?('sha384') then 'sha384'
                           elsif al.include?('sha512') then 'sha512'
                           elsif al.include?('sha1') then 'sha1'
                           elsif al.include?('md5') then 'md5'
                           else algo end
  end

  {
    signature_valid: signature_valid,
    signature_error: signature_error,
    subject: subject,
    subject_format: subject_format,
    issuer: issuer,
    audience: audience,
    attributes: attributes,
    assertion_count: assertions.length,
    assertion_id: assertion_id,
    selected_assertion_index: selected_assertion_index,
    selection_mode: selection_mode,
    reference_uri: reference_uri,
    reference_matches_selected_assertion: reference_matches_selected_assertion,
    signature_count: signature_count(doc),
    issuer_source: issuer_source,
    audience_count: audience_count,
    nameid_count: nameid_count,
    empty_nameid_semantics: empty_nameid_semantics,
    algorithms: algorithms,
    validated_signature_algorithm: signature_valid && sig_method ? sig_method.attributes['Algorithm'] : nil,
  }.to_json
end

# -- Main (skip when loaded as module) --
if __FILE__ == $0
  if ARGV.length < 1
    $stderr.puts 'Usage: ruby saml_rubysaml.rb <input_file>'
    exit 2
  end

  begin
    xml = File.read(ARGV[0], encoding: 'utf-8')
    puts verify_saml(xml)
    exit 0
  rescue => e
    $stderr.puts "REJECT: #{e.message}"
    exit 1
  end
end
