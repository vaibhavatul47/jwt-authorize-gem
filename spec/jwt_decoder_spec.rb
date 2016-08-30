require "spec_helper"

describe JwtAuthorize::JwtDecoder do
  describe ".get_payload_from_jwt" do
    let(:jwt_decoder) { JwtAuthorize::JwtDecoder.new }
    let(:cert) { certificate }

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

    let(:headers) do
      {
        "typ" => "JWT",
        "alg" => "RS256",
        "x5u" => "https://s3.amazonaws.com/be-secure-dev/dev.cer",
        "x5t" => thumbprint
      }
    end

    let(:invalid_jwt) do
      "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9
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

    it "fail if JWT is nil" do
      expect { jwt_decoder.get_payload_from_jwt(nil, cert) }
        .to raise_error("Header is nil!")
    end

    it "fail if header is not formatted as 'bearer jwttoken'" do
      expect { jwt_decoder.get_payload_from_jwt("somethingsomethingsomething", cert) }
        .to raise_error("Incorrectly formatted token")
    end

    it "fail if wrong public key is used" do
      expect { jwt_decoder.get_payload_from_jwt(invalid_jwt, cert) }
        .to raise_error("Payload could not be decoded from token.")
    end

    it "fail if JWT is expired" do
      expect { jwt_decoder.get_payload_from_jwt("bearer #{generate_jwt(expired_payload)}", cert) }
        .to raise_error("Payload could not be decoded from token.")
    end

    it "returns a payload" do
      # Get payload here because re-get will get new timestamp.
      payload = valid_payload
      result = jwt_decoder.get_payload_from_jwt("bearer #{generate_jwt(payload)}", cert)
      expect(result).to eq([payload, headers])
    end

    it "decodes a header" do
      header = jwt_decoder.get_headers_from_jwt("bearer #{generate_jwt(valid_payload)}")
      expect(header).to eq(headers)
    end
  end
end
