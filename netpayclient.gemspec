lib = File.expand_path('../lib', __FILE__)
# coding: utf-8
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'netpayclient/version'

Gem::Specification.new do |spec|
  spec.name          = "netpayclient"
  spec.version       = Netpayclient::VERSION
  spec.authors       = ["Weirong Xu"]
  spec.email         = ["weirongxu.raidou@gmail.com"]
  spec.licenses      = ['MIT']

  spec.summary       = %q{银联商户会员的ruby SDK}
  spec.description   = %q{银联商户会员的ruby SDK}
  spec.homepage      = "https://github.com/weirongxu/netpayclient"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "iniparse", "~> 1.4.2"
  spec.add_dependency "ruby-mcrypt", "~> 0.2.0"

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
