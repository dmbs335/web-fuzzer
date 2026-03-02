# Persistent module -- ruby-saml SAML verifier.
#
# Exports process(input) for use with persistent_wrapper.rb.

require_relative 'saml_rubysaml'

def process(input_str)
  # Guard: empty or clearly non-XML input
  if input_str.nil? || input_str.strip.empty? || !input_str.include?('<')
    return { output: '', exit_code: 1 }
  end

  begin
    output = verify_saml(input_str)
    { output: output.is_a?(String) ? output : output.to_s, exit_code: 0 }
  rescue => e
    $stderr.puts "ruby-saml error: #{e.class}: #{e.message}" rescue nil
    { output: '', exit_code: 1 }
  end
end
