# Persistent module -- Ruby WEBrick cookie parser.
#
# Exports process(input) for use with persistent_wrapper.rb.

require 'webrick'
require 'json'

def process(input_str)
  data = input_str.strip
  raise 'Empty input' if data.empty?

  c = WEBrick::Cookie.parse_set_cookie(data)
  raise 'No cookies parsed' if c.nil?

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

  { output: JSON.generate(result), exit_code: 0 }
rescue => e
  { output: '', exit_code: 1 }
end
