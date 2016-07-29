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

module JwtAuthorize
  class JwtDecoder
    def initialize(public_key = nil)
      @public_key = public_key
    end

    def get_payload_from_jwt(header)
      validate_header(header)

      token = token_from_header(header)

      decode_token(token).first
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

    def decode_token(token)
      JWT.decode(token, @public_key, true, algorithm: "RS256")
    rescue JWT::ExpiredSignature, JWT::VerificationError
      raise "Payload could not be decoded from token."
    end
  end
end
