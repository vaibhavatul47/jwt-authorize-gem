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

    let(:not_yet_valid_token) do
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
        "exp" => Time.new.to_i + 3600,
        "nbf" => Time.new.to_i + 120
      }
    end

    let(:base_repo) { "org/repo" }
    let(:permissions) { "pipeline.admin,pipeline.deploy" }

    it "returns true if JWT is valid." do
      expect(
        JwtAuthorize.authorized?(
          certificate,
          "bearer #{generate_jwt(valid_payload)}",
          permissions,
          base_repo))
        .to eq(true)
    end

    context "when NBF mentioned inside JWT has not reached" do
      it "returns false if no leeway is used" do
        expect(
          JwtAuthorize.authorized?(
            certificate,
            "bearer #{generate_jwt(not_yet_valid_token)}",
            permissions,
            base_repo
          )
        )
        .to eq(false)
      end

      it "returns true if nbf is within leeway limits" do
        expect(
          JwtAuthorize.authorized?(
            certificate,
            "bearer #{generate_jwt(not_yet_valid_token)}",
            permissions,
            base_repo,
            leeway: 120
          )
        )
        .to eq(true)
      end

      it "returns false if nbf is out of leeway limits" do
        expect(
          JwtAuthorize.authorized?(
            certificate,
            "bearer #{generate_jwt(not_yet_valid_token)}",
            permissions,
            base_repo,
            leeway: 60
          )
        )
        .to eq(false)
      end
    end

    it "returns false if JWT is invalid" do
      expect(
        JwtAuthorize.authorized?(
          certificate,
          "bearer #{generate_jwt(expired_payload)}",
          permissions,
          base_repo))
        .to eq(false)
    end

    it "returns the cert thumbprint" do
      expect(
        JwtAuthorize.get_certificate_thumbprint("bearer #{generate_jwt(valid_payload)}"))
        .to eq(thumbprint)
    end

    it "returns the cert path" do
      expect(
        JwtAuthorize.get_certificate_path("bearer #{generate_jwt(valid_payload)}"))
        .to eq(key_path)
    end

    it "returns the thumbprint key" do
      expect(JwtAuthorize::CERTIFICATE_THUMBPRINT).to eq("x5t")
    end

    it "returns the cert path key" do
      expect(JwtAuthorize::CERTIFICATE_PATH).to eq("x5u")
    end
  end
end
