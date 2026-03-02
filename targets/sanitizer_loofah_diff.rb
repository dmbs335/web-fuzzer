#!/usr/bin/env ruby
# Loofah differential target (process mode).
#
# Usage: ruby sanitizer_loofah_diff.rb <input_file>
# Output: Standardized JSON with security signals.

require_relative 'sanitizer_diff_common'
require 'loofah'
require 'json'

if ARGV.length < 1
  $stderr.puts 'Usage: ruby sanitizer_loofah_diff.rb <input_file>'
  exit 1
end

begin
  html = File.read(ARGV[0], encoding: 'utf-8')
  clean = Loofah.fragment(html).scrub!(:prune).to_s
  $stdout.write(JSON.generate(build_result(clean)))
rescue => e
  $stdout.write(JSON.generate({ 'error' => e.message, 'empty_output' => true }))
  exit 1
end
