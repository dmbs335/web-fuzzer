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
  REXML::XPath.each(doc, '//ds:Reference', 'ds' => DS_NS) do |ref|
    uri = ref.attributes['URI'] || ''
    if uri.start_with?('#')
      target_id = uri[1..]
      assertions.each do |a|
        if a.attributes['ID'] == target_id
          signed_assertion = a
          break
        end
      end
      break if signed_assertion
    end
  end
  signed_assertion ||= assertions[0]

  subject = nil
  subject_format = nil
  issuer = nil
  audience = nil
  attributes = {}

  if signed_assertion
    name_ids = REXML::XPath.match(signed_assertion, './/saml:NameID', 'saml' => SAML_NS)
    unless name_ids.empty?
      subject = name_ids[0].text&.strip
      subject_format = name_ids[0].attributes['Format']
    end

    issuers = REXML::XPath.match(signed_assertion, 'saml:Issuer', 'saml' => SAML_NS)
    issuer = issuers[0].text&.strip unless issuers.empty?

    audiences = REXML::XPath.match(signed_assertion, './/saml:Audience', 'saml' => SAML_NS)
    audience = audiences[0].text&.strip unless audiences.empty?

    REXML::XPath.each(signed_assertion, './/saml:Attribute', 'saml' => SAML_NS) do |attr|
      name = attr.attributes['Name']
      vals = REXML::XPath.match(attr, 'saml:AttributeValue', 'saml' => SAML_NS)
        .map { |v| v.text&.strip }
        .compact
      attributes[name] = vals.length == 1 ? vals[0] : vals if name && !vals.empty?
    end
  end

  # Response-level issuer as fallback
  unless issuer
    resp_issuers = REXML::XPath.match(doc, '//saml:Issuer', 'saml' => SAML_NS)
    issuer = resp_issuers[0].text&.strip unless resp_issuers.empty?
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
    algorithms: algorithms,
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
