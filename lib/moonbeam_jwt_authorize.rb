require "moonbeam_jwt_authorize/version"
require "moonbeam_jwt_authorize/authorization_helper"
require "logger"

module MoonbeamJwtAuthorize
  class << self
    attr_writer :logger

    def logger
      @logger ||= Logger.new($stdout).tap do |log|
        log.progname = name
      end
    end
  end

  def self.authorized?(public_key, auth_token, base_repo)
    auth_helper.authorized?(public_key, auth_token, base_repo)
  end

  def self.auth_helper
    @auth_helper ||= AuthorizationHelper.new
  end
end
