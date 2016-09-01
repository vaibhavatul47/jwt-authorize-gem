#  Copyright 2016 Adobe Systems Incorporated. All rights reserved.
#  This file is licensed to you under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License. You may obtain a copy
#  of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under
#  the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
#  OF ANY KIND, either express or implied. See the License for the specific language
#  governing permissions and limitations under the License.

require "jwt_authorize/version"
require "jwt_authorize/jwt_decoder"
require "jwt_authorize/jwt_payload_authorizer"
require "jwt_authorize/jwt_consts"
require "logger"

module JwtAuthorize
  class << self
    attr_writer :logger

    def get_certificate_thumbprint(auth_token)
      headers = get_jwt_headers(auth_token)

      headers[CERTIFICATE_THUMBPRINT]
    end

    def get_certificate_path(auth_token)
      headers = get_jwt_headers(auth_token)

      headers[CERTIFICATE_PATH]
    end

    def get_jwt_headers(auth_token)
      JwtAuthorize::JwtDecoder.new.get_headers_from_jwt(auth_token)
    end

    def decode(auth_token, certificate)
      fail "No public key" if certificate.nil?

      JwtAuthorize::JwtDecoder.new(logger).get_payload_from_jwt(auth_token, certificate)
    rescue => err
      logger.error("Error decoding JWT token: #{err}")
      nil
    end

    def authorized_request?(payload, permissions, base_repo)
      JwtAuthorize::JwtPayloadAuthorizer.new(permissions, logger).authorized?(payload, base_repo)
    rescue => err
      logger.error("Error processing JWT token: #{err}")
      false
    end

    def authorized?(certificate, auth_token, permissions, base_repo)
      decoded = decode(auth_token, certificate)

      decoded.nil? ? false : authorized_request?(decoded.first, permissions, base_repo)
    end

    def logger
      @logger ||= Logger.new($stdout).tap do |log|
        log.progname = name
      end
    end
  end
end
