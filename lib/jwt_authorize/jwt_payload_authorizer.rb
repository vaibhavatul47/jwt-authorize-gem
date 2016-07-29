#  Copyright 2016 Adobe Systems Incorporated. All rights reserved.
#  This file is licensed to you under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License. You may obtain a copy
#  of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under
#  the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
#  OF ANY KIND, either express or implied. See the License for the specific language
#  governing permissions and limitations under the License.

module JwtAuthorize
  class JwtPayloadAuthorizer
    def authorized?(payload, base_repo)
      repos = payload["repositories"]

      same_repositories?(repos, base_repo) && permissions_valid?(repos)
    end

    private

    def same_repositories?(payload_repos, base_repo)
      # same = payload_repos.map { |repo| repo["name"] }.include?(base_repo)
      test_repos = payload_repos.map { |repo| repo["name"] }
      fail "No payload repositories." if test_repos.size == 0

      same = test_repos.include?(base_repo)
      fail "Repositories do not match." unless same

      same
    end

    def permissions_valid?(payload_repos)
      needed_perms = permissions
      repo_perms = payload_repos.map { |repo| repo["permissions"] }.flatten

      valid = (needed_perms & repo_perms).size > 0

      fail "Invalid permissions." unless valid

      valid
    end

    def permissions
      perms = ENV.fetch("REQUIRED_DEPLOY_PERMISSIONS", "").downcase
      fail "REQUIRED_DEPLOY_PERMISSIONS is undefined" if perms.empty?

      perms.split(",")
    end
  end
end
