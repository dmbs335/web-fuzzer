# Loofah differential fuzzing module for persistent wrapper.

require_relative 'sanitizer_diff_common'
require 'loofah'
require 'json'

def process(input_str)
  begin
    clean = Loofah.fragment(input_str).scrub!(:prune).to_s
    { output: JSON.generate(build_result(clean)), exit_code: 0 }
  rescue => e
    { output: JSON.generate({ 'error' => e.message, 'empty_output' => true }), exit_code: 1 }
  end
end
