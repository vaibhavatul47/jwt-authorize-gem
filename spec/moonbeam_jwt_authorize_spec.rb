require "spec_helper"
require "support/jwt_helpers"

describe MoonbeamJwtAuthorize do
  include JwtHelpers

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
          "name" => "behance/moonbeam_faker",
          "permissions" => ["pipeline.admin"]
        }
      ],
      "exp" => 1_469_148_692
    }
  end

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
          "name" => "behance/moonbeam_faker",
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
          "name" => "behance/moonbeam_faker",
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
          "name" => "behance/moonbeam_faker_test",
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
      "exp" => Time.new.to_i
    }
  end

  let(:expired_token) do
    "token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9
    .eyJ1c2VyIjp7InVzZXJfaWQiOjY1OTIxOTYsInVzZXJuYW1lIjoiZGF2ZX
    BlcnNpbmcifSwicmVwb3NpdG9yaWVzIjpbeyJuYW1lIjoiYmVoYW5jZS9tb
    29uYmVhbV9mYWtlciIsInBlcm1pc3Npb25zIjpbInBpcGVsaW5lLmFkbWlu
    Il19XSwiZXhwIjoxNDY5MDM4NTQyfQ.xZyOL5LKMSASLSF3K5Om06Jk7knv
    Tc7v3JAv5V0Mo1aEiJzU-N_e45uvJlwSFuqB1Mv91LGYQ0w1VX1iYjM0AoL
    EF6zpZai1qOB2wUWbnA46CBLu3pbMdW8mYv9HNdMJOX-yOF9HfvN-2NHd2q
    8hE8pyXep4crY8IF6uLbC5iB8S4-ArzI-kfb178n6d7JoRW09BS1mE132Dv
    nDXXWT7hkbJmdwwixUe7Vgugov2o-KDJeALa143oduM3Bda78ux6_cMR3YI
    M3FO9_gXteYxWz69Wp0L-xxGxOLmDy7Bei8Dyb1DNs3vGMdIOt4tn7qhzOf
    Axb-VBU4fUrxylB3TrA"
  end

  let(:base_repo) { "behance/moonbeam_faker" }

  it "has a version number" do
    expect(MoonbeamJwtAuthorize::VERSION).not_to be nil
  end

  it "fails when public key is nil" do
    expect(
      MoonbeamJwtAuthorize.authorized?(
        nil,
        "token #{generate_jwt(valid_payload)}",
        base_repo)).to eq(false)
  end

  it "fails when auth header is nil" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, nil, base_repo)).to eq(false)
  end

  it "fails when auth header is empty string" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, "", base_repo)).to eq(false)
  end

  it "fails when base_repo is nil" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, expired_token, nil)).to eq(false)
  end

  it "fails when base_repo is empty string" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, expired_token, "")).to eq(false)
  end

  it "fails when JWT is invalid" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, "invalid", base_repo)).to eq(false)
  end

  it "fails with JWT is expired error" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, expired_token, base_repo)).to eq(false)
  end

  it "fails if permissions are insufficient" do
    expect(
      MoonbeamJwtAuthorize.authorized?(
        public_key,
        "token #{generate_jwt(insufficient_permissions_payload)}",
        base_repo))
      .to eq(false)
  end

  it "fails if repository doesn't match payload repository" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, "token #{generate_jwt(repo_mismatch_payload)}", base_repo))
      .to eq(false)
  end

  it "fails if repositories don't exist in payload" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, "token #{generate_jwt(no_repos_payload)}", base_repo))
      .to eq(false)
  end

  it "succeeds in validating JWT" do
    expect(MoonbeamJwtAuthorize.authorized?(public_key, "token #{generate_jwt(valid_payload)}", base_repo)).to eq(true)
  end
end
