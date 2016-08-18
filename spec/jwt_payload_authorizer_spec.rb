require "spec_helper"

describe JwtAuthorize::JwtPayloadAuthorizer do
  describe ".authorized?" do
    let(:valid_payload) do
      {
        "user" =>
        {
          "user_id" => 1_234_567,
          "username" => "test_user"
        },
        "repositories" =>
        [
          {
            "name" => "org/repo",
            "permissions" => ["pipeline.admin"]
          }
        ],
        "exp" => Time.new.to_i + 3600
      }
    end

    let(:insufficient_permissions_payload) do
      {
        "user" =>
        {
          "user_id" => 1_234_567,
          "username" => "test_user"
        },
        "repositories" =>
        [
          {
            "name" => "org/repo",
            "permissions" => [""]
          }
        ],
        "exp" => Time.new.to_i + 3600
      }
    end

    let(:repo_mismatch_payload) do
      {
        "user" =>
        {
          "user_id" => 1_234_567,
          "username" => "test_user"
        },
        "repositories" =>
        [
          {
            "name" => "org/repo_test",
            "permissions" => ["pipeline.admin"]
          }
        ],
        "exp" => Time.new.to_i + 3600
      }
    end

    let(:no_repos_payload) do
      {
        "user" =>
        {
          "user_id" => 1_234_567,
          "username" => "test_user"
        },
        "repositories" => [],
        "exp" => Time.new.to_i + 3600
      }
    end

    let(:permissions) { "pipeline.admin,pipeline.deploy" }
    let(:authorizer) { JwtAuthorize::JwtPayloadAuthorizer.new(permissions) }
    let(:base_repo) { "org/repo" }
    let(:upper_case_base_repo) { "ORg/rEpo" }

    it "fails if no repositories exist in payload" do
      expect { authorizer.authorized?(no_repos_payload, base_repo) }
        .to raise_error("No payload repositories.")
    end

    it "fails if permissions are insufficient" do
      expect { authorizer.authorized?(insufficient_permissions_payload, base_repo) }
        .to raise_error("Invalid permissions.")
    end

    it "fails if repositories do not match payload repos" do
      expect { authorizer.authorized?(repo_mismatch_payload, base_repo) }.to raise_error("Repositories do not match.")
    end

    it "succeeds if repo letter cases mismatch" do
      expect(authorizer.authorized?(valid_payload, upper_case_base_repo)).to eq(true)
    end

    it "succeeds if repos are the same and user has permissions" do
      expect(authorizer.authorized?(valid_payload, base_repo)).to eq(true)
    end
  end
end
