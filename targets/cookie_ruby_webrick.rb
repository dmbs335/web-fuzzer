#!/usr/bin/env ruby
# Cookie parser target -- Ruby WEBrick.
#
# Parses Set-Cookie header values using WEBrick::Cookie.parse_set_cookie
# and outputs parsed components as JSON for differential comparison.
#
# WEBrick is Ruby's stdlib HTTP server with built-in cookie parsing.
# It follows RFC 6265 loosely and has known quirks around quoted
# values, whitespace handling, and attribute casing.
#
# References:
#   - RFC 6265bis (Cookies: HTTP State Management Mechanism)
#   - Ruby docs: WEBrick::Cookie
#   - Cookie Crumbles (USENIX Security 2023) -- 12 CVEs across frameworks

require 'webrick'
require 'json'

def parse_cookie(data)
  data = data.strip
  raise 'Empty input' if data.empty?

  c = WEBrick::Cookie.parse_set_cookie(data)
  raise 'No cookies parsed' if c.nil?

  # WEBrick::Cookie may not expose httponly in all versions
  httponly_val = c.respond_to?(:httponly) ? !!c.httponly : false

  result = {
    name: c.name || '',
    value: c.value || '',
    domain: c.domain || '',
    path: c.path || '',
    expires: c.expires ? c.expires.utc.strftime('%a, %d %b %Y %H:%M:%S GMT') : '',
    max_age: c.max_age ? c.max_age.to_s : '',
    secure: !!c.secure,
    httponly: httponly_val,
    samesite: '',
    version: c.version ? c.version.to_s : ''
  }

  JSON.generate(result)
end

if ARGV.length < 1
  $stderr.puts 'Usage: ruby cookie_ruby_webrick.rb <file>'
  exit 2
end

begin
  data = File.read(ARGV[0], encoding: 'UTF-8')
rescue => e
  $stderr.puts "IO error: #{e.message}"
  exit 2
end

begin
  result = parse_cookie(data)
  puts result
  exit 0
rescue => e
  $stderr.puts "REJECT: #{e.message}"
  exit 1
end
