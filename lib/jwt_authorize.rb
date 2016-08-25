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
require "logger"

module JwtAuthorize
  class << self
    attr_writer :logger

    def logger
      @logger ||= Logger.new($stdout).tap do |log|
        log.progname = name
      end
    end
  end

  def self.decode(auth_token, certificate)
    fail "No public key" if certificate.nil?

    JwtAuthorize::JwtDecoder.new.get_payload_from_jwt(auth_token, certificate)
  rescue => err
    logger.error("Error decoding JWT token: #{err}")
    nil
  end

  def self.authorized?(payload, permissions, base_repo)
    JwtAuthorize::JwtPayloadAuthorizer.new(permissions).authorized?(payload, base_repo)
  rescue => err
    logger.error("Error processing JWT token: #{err}")
    false
  end

  def self.decode_and_authorized?(certificate, auth_token, permissions, base_repo)
    decoded = decode(auth_token, certificate)

    decoded.nil? ? false : authorized?(decoded.first, permissions, base_repo)
  end
end
