# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "jwt_authorize/version"

Gem::Specification.new do |spec|
  spec.name          = "jwt_authorize"
  spec.version       = JwtAuthorize::VERSION
  spec.authors       = ["Dave Persing"]
  spec.email         = ["persing@adobe.com"]

  spec.summary       = "Authorizing requests containing an Authorization header against custom permissions"
  spec.homepage      = "https://github.com/adobe-platform/jwt-authorize-gem"

  spec.files = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop"

  spec.add_dependency "jwt", "~> 1.5"
end
