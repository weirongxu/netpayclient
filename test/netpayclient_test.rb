require 'test_helper'

class NetpayclientTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Netpayclient::VERSION
  end
end
