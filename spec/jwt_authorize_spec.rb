require "spec_helper"

describe JwtAuthorize do
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

    let(:expired_payload) do
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
        "exp" => 1_469_148_692
      }
    end

    let(:base_repo) { "org/repo" }

    it "returns true if JWT is valid." do
      expect(JwtAuthorize.authorized?(public_key, "bearer #{generate_jwt(valid_payload)}", base_repo)).to eq(true)
    end

    it "returns false if JWT is invalid" do
      expect(JwtAuthorize.authorized?(public_key, "bearer #{generate_jwt(expired_payload)}", base_repo)).to eq(false)
    end
  end
end
