require "jwt"

module MoonbeamJwtAuthorize
  class AuthorizationHelper
    def authorized?(public_key, header, base_repo)
      check_public_key(public_key)
      validate_params(header, base_repo)

      token = token_from_header(header)
      payload = decode_token(public_key, token).first

      check_repo_and_perms(payload, base_repo)
    rescue => e
      log(e.message)
      false
    end

    private

    def check_repo_and_perms(payload, base_repo)
      repos = payload["repositories"]

      same_repos = same_repositories?(repos, base_repo)
      fail "Repos do not match.  #{repos.inspect} and #{base_repo}" unless same_repos
      perms_valid = permissions_valid?(repos)
      fail "Required permissions have not been granted." unless perms_valid

      same_repos && perms_valid
    end

    def validate_params(header, base_repo)
      fail "Header #{header} is nil!" if header.nil?
      fail "Base repo #{base_repo} is nil!" if base_repo.nil?
    end

    def check_public_key(public_key)
      fail "public key is undefined" if public_key.nil?
    end

    def token_from_header(header)
      _type, token = header.split(" ", 2)
      fail "#{header} is invalid token!" unless token

      token
    end

    def decode_token(public_key, token)
      decoded = JWT.decode(token, public_key, true, algorithm: "RS256")
      fail "Payload cannot be decoded from token" unless decoded

      decoded
    end

    def same_repositories?(repos, base_repo)
      fail "Repositories cannot be extracted from payload" unless repos

      repos.collect { |repo| repo["name"] }.include?(base_repo)
    end

    def permissions_valid?(repos)
      repo_perms = repos.collect { |repo| repo["permissions"] }.flatten

      (permissions & repo_perms).size > 0
    end

    def permissions
      fail "REQUIRED_DEPLOY_PERMISSIONS is undefined!" unless ENV["REQUIRED_DEPLOY_PERMISSIONS"]

      ENV["REQUIRED_DEPLOY_PERMISSIONS"].split(",")
    end

    def log(message)
      MoonbeamJwtAuthorize.logger.info(message)
    end
  end
end
