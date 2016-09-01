require "jwt"

module JwtHelper
  def generate_jwt(payload)
    JWT.encode(payload, private_key, "RS256", header_options)
  end

  def private_key
    key
  end

  def public_key
    @certificate.public_key || new_cert
  end

  def key
    @key ||= new_key
  end

  def certificate
    @certificate ||= generate_cert
  end

  def key_path
    "https://s3.amazonaws.com/be-secure-dev/dev.cer"
  end

  def generate_cert
    cert = new_cert(key)
    cert = cert.sign key, OpenSSL::Digest::SHA256.new

    cert
  end

  def new_key
    OpenSSL::PKey::RSA.generate 2048
  end

  def new_cert(key = nil)
    subject = "/C=US/O=Test/OU=Test/CN=Test"

    cert = OpenSSL::X509::Certificate.new
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)
    cert.not_before = Time.now
    cert.not_after = Time.now + 365 * 24 * 60 * 60
    cert.public_key = key.public_key
    cert.serial = 0x0
    cert.version = 2

    cert
  end

  def header_options
    {
      x5u: key_path,
      x5t: thumbprint
    }
  end

  def thumbprint
    OpenSSL::Digest::SHA1.hexdigest(certificate.to_der).scan(/../).join(":")
  end
end
