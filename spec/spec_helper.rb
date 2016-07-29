$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "jwt_authorize"
require "support/jwt_helper"

RSpec.configure do |config|
  config.include JwtHelper
end
