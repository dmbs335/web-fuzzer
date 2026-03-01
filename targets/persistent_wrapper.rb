#!/usr/bin/env ruby
# Persistent wrapper for Ruby fuzzing target modules.
#
# Keeps Ruby process alive and reuses loaded modules.
# Protocol: length-prefixed binary over stdin/stdout.
#
#   Request:  [4-byte BE length][input bytes]
#   Response: [4-byte BE length][output bytes][4-byte BE exit code]
#
# Module must define a top-level `process(input)` method returning
# { output: String, exit_code: Integer }.
#
# Usage: ruby persistent_wrapper.rb ./module_path.rb

if ARGV.length < 1
  $stderr.puts 'Usage: ruby persistent_wrapper.rb <module_path>'
  exit 1
end

module_path = File.expand_path(ARGV[0])
require module_path

$stdin.binmode
$stdout.binmode
$stdout.sync = true

loop do
  # Read 4-byte BE length header
  header = $stdin.read(4)
  break if header.nil? || header.length < 4

  length = header.unpack1('N')

  # Read input data
  data = $stdin.read(length)
  break if data.nil? || data.length < length

  input_str = data.force_encoding('UTF-8')

  output = ''
  exit_code = 0
  begin
    result = process(input_str)
    output = result[:output] || ''
    exit_code = result[:exit_code] || 0
  rescue => e
    output = ''
    exit_code = 1
    $stderr.puts "Error: #{e.message}"
  end

  out_bytes = output.encode('UTF-8').b
  # Response: [4-byte len][output][4-byte exit code]
  resp = [out_bytes.length].pack('N') + out_bytes + [exit_code].pack('N')
  $stdout.write(resp)
end
