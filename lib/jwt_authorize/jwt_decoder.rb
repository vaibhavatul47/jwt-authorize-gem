#  Copyright 2016 Adobe Systems Incorporated. All rights reserved.
#  This file is licensed to you under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License. You may obtain a copy
#  of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under
#  the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
#  OF ANY KIND, either express or implied. See the License for the specific language
#  governing permissions and limitations under the License.

require "jwt"
require "jwt_authorize/jwt_consts"

module JwtAuthorize
  class JwtDecoder
    def initialize(logger = nil, options = {})
      @logger = logger
      @options = options
    end

    def get_payload_from_jwt(header, certificate)
      fail "No certificate specified" unless certificate

      validate_header(header)

      token = token_from_header(header)

      decoded = decode_token(token, certificate)

      options = decoded.last
      validate_thumbprint(options[CERTIFICATE_THUMBPRINT], certificate)

      decoded
    end

    def get_headers_from_jwt(token)
      fail "token is nil" if token.nil?

      headers = token_from_header(token).split(".").first

      JSON.parse(Base64.decode64(headers))
    end

    private

    def validate_header(header)
      fail "Header is nil!" if header.nil?
      fail "Incorrectly formatted token" unless header.start_with?("bearer")
    end

    def token_from_header(header)
      _type, token = header.split(" ", 2)
      fail "#{header} is invalid token!" unless token

      token
    end

    def validate_thumbprint(head_thumb, certificate)
      cert_thumb = calculate_thumbprint(certificate)
      fail "Cert SHA1 mismatch. head: #{head_thumb}, cert: #{cert_thumb}" unless head_thumb.casecmp(cert_thumb)
    end

    def decode_token(token, certificate)
      @options[:algorithm] = "RS256"
      JWT.decode(token, certificate.public_key, true, @options)
    rescue JWT::ExpiredSignature, JWT::VerificationError => err
      @logger.error("Payload could not be decoded: #{err}") unless @logger.nil?
      raise "Payload could not be decoded from token."
    end

    def calculate_thumbprint(certificate)
      OpenSSL::Digest::SHA1.hexdigest(certificate.to_der).scan(/../).join(":")
    end
  end
end
