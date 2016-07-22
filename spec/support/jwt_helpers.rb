require "jwt"

module JwtHelpers
  def generate_jwt(payload)
    JWT.encode(payload, private_key, "RS256")
  end

  def private_key
    key
  end

  def public_key
    key.public_key
  end

  def key
    @key ||= OpenSSL::PKey::RSA.generate 2048
  end
end

RSpec.configure do |c|
  c.include JwtHelpers
end
